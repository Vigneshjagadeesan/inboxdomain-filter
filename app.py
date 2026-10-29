import streamlit as st
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import re

st.set_page_config(page_title="DMARC Live Inspector", layout="wide", page_icon="🛡️")

st.title("🛡️ Accurate DMARC Policy Analyzer")
st.caption("Robust DNS resolution & Regex pattern matching.")

# Fallback resolvers setup
def get_resolver():
    res = dns.resolver.Resolver()
    res.timeout = 4.0
    res.lifetime = 4.0
    # Try public DNS; fallback to system resolver if restricted
    res.nameservers = ['1.1.1.1', '8.8.8.8']
    return res

resolver = get_resolver()

def check_domain(domain):
    domain = domain.strip().lower()
    # Strip URL formatting
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    # Strip www if needed, but keep core domain
    if domain.startswith("www."):
        domain = domain[4:]

    if not domain or "." not in domain:
        return None

    dmarc_query = f"_dmarc.{domain}"
    raw_txt_records = []
    
    try:
        answers = resolver.resolve(dmarc_query, "TXT")
        for rdata in answers:
            # Join multiple string segments if chunked
            record = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
            raw_txt_records.append(record)
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "status": "No DMARC", "policy": "none_found", "record": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "status": "No DMARC", "policy": "none_found", "record": "No TXT Record"}
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        # Fallback to default system DNS if 1.1.1.1 / 8.8.8.8 times out
        try:
            default_resolver = dns.resolver.Resolver()
            default_resolver.timeout = 4.0
            answers = default_resolver.resolve(dmarc_query, "TXT")
            for rdata in answers:
                record = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
                raw_txt_records.append(record)
        except Exception as e:
            return {"domain": domain, "status": "DNS Error/Timeout", "policy": "error", "record": str(e)}
    except Exception as e:
        return {"domain": domain, "status": "No DMARC", "policy": "none_found", "record": str(e)}

    # Scan records for DMARC tag
    for txt in raw_txt_records:
        cleaned_txt = txt.strip().strip('"').strip("'")
        # Matches v=DMARC1 with flexible spacing/casing
        if re.search(r"\bv\s*=\s*DMARC1\b", cleaned_txt, re.IGNORECASE):
            # Extract p= policy using regex
            match = re.search(r"\bp\s*=\s*([a-zA-Z]+)", cleaned_txt, re.IGNORECASE)
            if match:
                policy = match.group(1).lower()
                if policy == "none":
                    return {"domain": domain, "status": "DMARC p=none", "policy": "none", "record": cleaned_txt}
                else:
                    return {"domain": domain, "status": f"DMARC p={policy}", "policy": policy, "record": cleaned_txt}
            return {"domain": domain, "status": "DMARC (No Policy Specified)", "policy": "unspecified", "record": cleaned_txt}

    return {"domain": domain, "status": "No DMARC", "policy": "none_found", "record": "; ".join(raw_txt_records) or "No DMARC record found"}

# UI
domains_text = st.text_area(
    "Domains list paste pannunga (one per line):",
    placeholder="google.com\nyahoo.com\nmicrosoft.com",
    height=200
)

col_run, col_threads = st.columns([2, 2])
with col_threads:
    threads = st.slider("Threads (koraicha accuracy koodum):", min_value=5, max_value=30, value=15)
with col_run:
    st.write("")
    st.write("")
    start_btn = st.button("🚀 Analyze & Split", type="primary", use_container_width=True)

if start_btn:
    raw_list = domains_text.splitlines()
    clean_domains = list(dict.fromkeys([d.strip() for d in raw_list if d.strip()]))

    if not clean_domains:
        st.warning("Domains ethuvum paste pannala!")
    else:
        progress_bar = st.progress(0)
        status_box = st.empty()
        results = []
        total = len(clean_domains)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for idx, res in enumerate(executor.map(check_domain, clean_domains)):
                if res:
                    results.append(res)
                progress_bar.progress((idx + 1) / total)
                status_box.text(f"Scanning {idx + 1}/{total}: {clean_domains[idx]}")

        status_box.success("Scan Completed!")
        df = pd.DataFrame(results)

        no_dmarc_df = df[df["status"] == "No DMARC"]
        dmarc_none_df = df[df["status"] == "DMARC p=none"]
        protected_df = df[df["policy"].isin(["quarantine", "reject"])]
        errors_df = df[df["status"] == "DNS Error/Timeout"]

        st.divider()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Tested", len(df))
        c2.metric("❌ No DMARC", len(no_dmarc_df))
        c3.metric("⚠️ p=none", len(dmarc_none_df))
        c4.metric("🛡️ Protected / Errors", f"{len(protected_df)} / {len(errors_df)}")

        st.divider()

        tab1, tab2, tab3 = st.tabs(["⚠️ DMARC p=none", "❌ No DMARC", "🔍 Full Inspection Details"])

        with tab1:
            st.subheader(f"DMARC p=none Domains ({len(dmarc_none_df)})")
            if not dmarc_none_df.empty:
                st.text_area("Direct Copy p=none:", value="\n".join(dmarc_none_df["domain"].tolist()), height=180)
                st.download_button("📥 Download p=none (.txt)", data="\n".join(dmarc_none_df["domain"].tolist()), file_name="p_none.txt")
            else:
                st.info("Zero domains with p=none.")

        with tab2:
            st.subheader(f"No DMARC Domains ({len(no_dmarc_df)})")
            if not no_dmarc_df.empty:
                st.text_area("Direct Copy No DMARC:", value="\n".join(no_dmarc_df["domain"].tolist()), height=180)
                st.download_button("📥 Download No DMARC (.txt)", data="\n".join(no_dmarc_df["domain"].tolist()), file_name="no_dmarc.txt")
            else:
                st.info("Zero domains without DMARC.")

        with tab3:
            st.subheader("Inspection Table (Domain, Status & Actual Record)")
            st.dataframe(df[["domain", "status", "record"]], use_container_width=True)
