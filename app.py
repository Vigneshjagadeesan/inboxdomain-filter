import streamlit as st
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import re

st.set_page_config(page_title="DMARC Live Inspector", layout="wide", page_icon="🛡️")

st.title("🛡️ Accurate DMARC Policy Analyzer")
st.caption("Filters by domain behind the scenes, but returns your original email/fname format in the results!")

def get_resolver():
    res = dns.resolver.Resolver()
    res.timeout = 3.0
    res.lifetime = 3.0
    res.nameservers = ['8.8.8.8', '1.1.1.1']
    return res

resolver = get_resolver()

def extract_clean_domain(raw_text):
    text = raw_text.strip().lower()
    if "@" in text:
        text = text.split("@")[-1]
    text = re.sub(r"^https?://", "", text)
    text = text.split("/")[0].strip()
    if text.startswith("www."):
        text = text[4:]
    return text

def check_domain(raw_input):
    original_line = raw_input.strip()
    domain = extract_clean_domain(original_line)

    if not domain or "." not in domain:
        return {
            "original": original_line,
            "domain": domain,
            "status": "Invalid Entry",
            "policy": "invalid",
            "record": "Invalid domain format"
        }

    dmarc_query = f"_dmarc.{domain}"
    raw_txt_records = []
    
    try:
        answers = resolver.resolve(dmarc_query, "TXT")
        for rdata in answers:
            txt_val = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
            raw_txt_records.append(txt_val)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            "original": original_line,
            "domain": domain,
            "status": "No DMARC",
            "policy": "none_found",
            "record": "No DMARC record"
        }
    except (dns.resolver.Timeout, dns.resolver.NoNameservers):
        try:
            default_resolver = dns.resolver.Resolver()
            default_resolver.timeout = 3.0
            answers = default_resolver.resolve(dmarc_query, "TXT")
            for rdata in answers:
                txt_val = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
                raw_txt_records.append(txt_val)
        except Exception:
            return {
                "original": original_line,
                "domain": domain,
                "status": "No DMARC",
                "policy": "none_found",
                "record": "DNS Timeout"
            }
    except Exception as e:
        return {
            "original": original_line,
            "domain": domain,
            "status": "No DMARC",
            "policy": "none_found",
            "record": str(e)
        }

    for txt in raw_txt_records:
        cleaned_txt = txt.strip().strip('"').strip("'")
        if re.search(r"\bv\s*=\s*DMARC1\b", cleaned_txt, re.IGNORECASE):
            match = re.search(r"\bp\s*=\s*([a-zA-Z]+)", cleaned_txt, re.IGNORECASE)
            if match:
                policy = match.group(1).lower()
                if policy == "none":
                    return {
                        "original": original_line,
                        "domain": domain,
                        "status": "DMARC p=none",
                        "policy": "none",
                        "record": cleaned_txt
                    }
                else:
                    return {
                        "original": original_line,
                        "domain": domain,
                        "status": f"DMARC p={policy}",
                        "policy": policy,
                        "record": cleaned_txt
                    }
            return {
                "original": original_line,
                "domain": domain,
                "status": "DMARC (No Policy)",
                "policy": "unspecified",
                "record": cleaned_txt
            }

    return {
        "original": original_line,
        "domain": domain,
        "status": "No DMARC",
        "policy": "none_found",
        "record": "; ".join(raw_txt_records)
    }

input_text = st.text_area(
    "List-ah inga paste pannunga (fname@domain.com or domains):",
    placeholder="john@example.com\nkarthi@testdomain.org\nsuresh@company.io",
    height=220
)

col_run, col_threads = st.columns([2, 2])
with col_threads:
    threads = st.slider("Scan Speed (Threads):", min_value=5, max_value=40, value=25)
with col_run:
    st.write("")
    st.write("")
    start_btn = st.button("🚀 Process & Retain Original", type="primary", use_container_width=True)

if start_btn:
    raw_lines = [line.strip() for line in input_text.splitlines() if line.strip()]

    if not raw_lines:
        st.warning("List ethuvum paste pannala!")
    else:
        progress_bar = st.progress(0)
        status_box = st.empty()
        results = []
        total = len(raw_lines)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for idx, res in enumerate(executor.map(check_domain, raw_lines)):
                if res:
                    results.append(res)
                progress_bar.progress((idx + 1) / total)
                status_box.text(f"Checked {idx + 1}/{total}: {res['domain']}")

        status_box.success("Scan Completed!")
        df = pd.DataFrame(results)

        no_dmarc_df = df[df["status"] == "No DMARC"]
        dmarc_none_df = df[df["status"] == "DMARC p=none"]
        protected_df = df[df["policy"].isin(["quarantine", "reject"])]

        st.divider()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Items", len(df))
        c2.metric("❌ No DMARC", len(no_dmarc_df))
        c3.metric("⚠️ DMARC p=none", len(dmarc_none_df))
        c4.metric("🛡️ Protected (reject/quar)", len(protected_df))

        st.divider()

        tab1, tab2, tab3 = st.tabs(["⚠️ DMARC p=none (Original format)", "❌ No DMARC (Original format)", "📋 Full Details"])

        with tab1:
            st.subheader(f"DMARC p=none ({len(dmarc_none_df)} items)")
            if not dmarc_none_df.empty:
                pnone_results = "\n".join(dmarc_none_df["original"].tolist())
                st.text_area("Direct Copy (With fname):", value=pnone_results, height=200, key="pnone_fname")
                st.download_button(
                    "📥 Download p=none (Original format)",
                    data=pnone_results,
                    file_name="p_none_with_fname.txt",
                    mime="text/plain",
                    key="dl_pnone"
                )
            else:
                st.info("Zero p=none records found.")

        with tab2:
            st.subheader(f"No DMARC ({len(no_dmarc_df)} items)")
            if not no_dmarc_df.empty:
                nodmarc_results = "\n".join(no_dmarc_df["original"].tolist())
                st.text_area("Direct Copy (With fname):", value=nodmarc_results, height=200, key="nodmarc_fname")
                st.download_button(
                    "📥 Download No DMARC (Original format)",
                    data=nodmarc_results,
                    file_name="no_dmarc_with_fname.txt",
                    mime="text/plain",
                    key="dl_nodmarc"
                )
            else:
                st.info("Zero No DMARC records found.")

        with tab3:
            st.subheader("All Scanned Rows")
            st.dataframe(df[["original", "domain", "status", "record"]], use_container_width=True)
