import streamlit as st
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import io

st.set_page_config(page_title="DMARC Bulk Inspector", layout="wide", page_icon="🛡️")

st.title("🛡️ DMARC Live Inspector & Splitter")
st.caption("Domains-ah direct-ah copy-paste pannunga — automatic-ah 'No DMARC' and 'p=none' nu split aagidum.")

# DNS Resolver setup
resolver = dns.resolver.Resolver()
resolver.timeout = 2.0
resolver.lifetime = 2.0
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

def check_domain(domain):
    domain = domain.strip().lower()
    # Clean protocols/paths if accidentally pasted
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not domain:
        return None
    
    dmarc_query = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(dmarc_query, "TXT")
        for rdata in answers:
            txt_record = "".join([part.decode('utf-8') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if txt_record.startswith("v=DMARC1"):
                tags = [tag.strip() for tag in txt_record.split(";")]
                for tag in tags:
                    if tag.startswith("p="):
                        policy = tag.split("=")[1].strip().lower()
                        if policy == "none":
                            return {"domain": domain, "status": "DMARC p=none", "record": txt_record}
                        else:
                            return {"domain": domain, "status": f"DMARC p={policy}", "record": txt_record}
                return {"domain": domain, "status": "No Policy Tag", "record": txt_record}
        return {"domain": domain, "status": "No DMARC", "record": ""}
    except Exception:
        return {"domain": domain, "status": "No DMARC", "record": ""}

# Mode selection: Bulk Paste vs Single Search
mode = st.radio("Search Type Choose Pannunga:", ["Bulk Paste (Multiple Domains)", "Single Domain Quick Check"], horizontal=True)

if mode == "Single Domain Quick Check":
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        single_domain = st.text_input("Enter Domain Name:", placeholder="example.com")
    with col_btn:
        st.write("") # Alignment spacing
        st.write("")
        search_btn = st.button("Check Domain", type="primary", use_container_width=True)

    if search_btn and single_domain:
        with st.spinner("Checking DNS..."):
            res = check_domain(single_domain)
            if res["status"] == "No DMARC":
                st.error(f"❌ **{res['domain']}** has **No DMARC** record configured.")
            elif res["status"] == "DMARC p=none":
                st.warning(f"⚠️ **{res['domain']}** has policy: **p=none** (Monitoring only, vulnerable to spoofing)")
                st.code(res["record"], language="text")
            else:
                st.success(f"✅ **{res['domain']}** is protected: **{res['status']}**")
                st.code(res["record"], language="text")

else:
    # Direct paste box for bulk
    domains_text = st.text_area(
        "Domains list paste pannunga (one domain per line):",
        placeholder="example1.com\nexample2.org\nexample3.io",
        height=220
    )

    col_btn, col_info = st.columns([2, 5])
    with col_btn:
        start_btn = st.button("🚀 Process Domains", type="primary", use_container_width=True)

    if start_btn:
        raw_list = domains_text.splitlines()
        clean_domains = list(dict.fromkeys([d.strip() for d in raw_list if d.strip()]))

        if not clean_domains:
            st.warning("Dayavu senju domains paste pannitu click pannunga!")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            results = []
            total = len(clean_domains)

            with ThreadPoolExecutor(max_workers=35) as executor:
                for idx, res in enumerate(executor.map(check_domain, clean_domains)):
                    if res:
                        results.append(res)
                    progress_bar.progress((idx + 1) / total)
                    status_text.text(f"Scanning {idx + 1} of {total} domains...")

            status_text.success("Scan Completed!")
            df = pd.DataFrame(results)

            no_dmarc_df = df[df["status"] == "No DMARC"]
            dmarc_none_df = df[df["status"] == "DMARC p=none"]
            protected_df = df[~df["status"].isin(["No DMARC", "DMARC p=none"])]

            # Metrics
            st.divider()
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Searched", len(df))
            m2.metric("No DMARC", len(no_dmarc_df))
            m3.metric("p=none", len(dmarc_none_df))
            m4.metric("Protected (reject/quarantine)", len(protected_df))

            st.divider()

            # Split view
            left_col, right_col = st.columns(2)

            with left_col:
                st.subheader(f"❌ No DMARC ({len(no_dmarc_df)})")
                if not no_dmarc_df.empty:
                    st.text_area(
                        "Direct Copy No DMARC:",
                        value="\n".join(no_dmarc_df["domain"].tolist()),
                        height=200,
                        key="no_dmarc_box"
                    )
                    st.download_button(
                        "📥 Download List (.txt)",
                        data="\n".join(no_dmarc_df["domain"].tolist()),
                        file_name="no_dmarc.txt",
                        mime="text/plain",
                        key="dl_no_dmarc"
                    )
                else:
                    st.info("No domains found without DMARC.")

            with right_col:
                st.subheader(f"⚠️ DMARC p=none ({len(dmarc_none_df)})")
                if not dmarc_none_df.empty:
                    st.text_area(
                        "Direct Copy p=none:",
                        value="\n".join(dmarc_none_df["domain"].tolist()),
                        height=200,
                        key="pnone_box"
                    )
                    st.download_button(
                        "📥 Download List (.txt)",
                        data="\n".join(dmarc_none_df["domain"].tolist()),
                        file_name="dmarc_pnone.txt",
                        mime="text/plain",
                        key="dl_pnone"
                    )
                else:
                    st.info("No domains found with p=none.")
