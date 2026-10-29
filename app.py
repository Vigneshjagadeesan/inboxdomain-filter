import streamlit as st
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import io

st.set_page_config(page_title="DMARC Bulk Splitter", layout="wide", page_icon="🛡️")

st.title("🛡️ Bulk DMARC Policy Analyzer & Splitter")
st.markdown("Upload a file with domains to categorize them into **No DMARC** and **DMARC p=none**.")

# DNS Resolver setup
resolver = dns.resolver.Resolver()
resolver.timeout = 2.5
resolver.lifetime = 2.5
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

def check_domain(domain):
    domain = domain.strip().lower()
    if not domain:
        return None
    
    dmarc_query = f"_dmarc.{domain}"
    try:
        answers = resolver.resolve(dmarc_query, "TXT")
        for rdata in answers:
            txt_record = "".join([part.decode('utf-8') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if txt_record.startswith("v=DMARC1"):
                # Tag extraction
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

# Sidebar settings
with st.sidebar:
    st.header("⚙️ Configuration")
    max_workers = st.slider("Concurrent Threads", min_value=10, max_value=60, value=30, step=5)
    st.info("Tip: 30-40 threads is optimal for speed without getting DNS rate-limited.")

# File uploader (supports TXT and CSV)
uploaded_file = st.file_uploader("Upload Domain List (TXT or CSV)", type=["txt", "csv"])

domains = []
if uploaded_file is not None:
    if uploaded_file.name.endswith(".txt"):
        content = uploaded_file.read().decode("utf-8")
        domains = [line.strip() for line in content.splitlines() if line.strip()]
    elif uploaded_file.name.endswith(".csv"):
        df_input = pd.read_csv(uploaded_file)
        # Select first column or domain column
        col_name = df_input.columns[0]
        domains = df_input[col_name].dropna().astype(str).str.strip().tolist()

    st.write(f"Total domains loaded: **{len(domains)}**")

    if st.button("Start Bulk Scan", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        results = []
        total = len(domains)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for idx, res in enumerate(executor.map(check_domain, domains)):
                if res:
                    results.append(res)
                # Update progress
                progress = (idx + 1) / total
                progress_bar.progress(progress)
                status_text.text(f"Processed {idx + 1} of {total} domains...")

        status_text.success("Scan Completed!")
        
        # Convert results to DataFrame
        df_results = pd.DataFrame(results)

        # Categorize
        no_dmarc_df = df_results[df_results["status"] == "No DMARC"]
        dmarc_none_df = df_results[df_results["status"] == "DMARC p=none"]
        other_df = df_results[~df_results["status"].isin(["No DMARC", "DMARC p=none"])]

        # Dashboard Metrics
        st.divider()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Processed", len(df_results))
        col2.metric("No DMARC", len(no_dmarc_df))
        col3.metric("DMARC p=none", len(dmarc_none_df))
        col4.metric("Other (reject/quarantine)", len(other_df))

        st.divider()

        # Tabs for downloading and viewing
        tab1, tab2, tab3 = st.tabs(["❌ No DMARC", "⚠️ DMARC p=none", "📋 Full Results"])

        with tab1:
            st.subheader(f"No DMARC Records ({len(no_dmarc_df)})")
            st.dataframe(no_dmarc_df[["domain"]], use_container_width=True)
            
            # Download TXT button
            no_dmarc_txt = "\n".join(no_dmarc_df["domain"].tolist())
            st.download_button(
                label="📥 Download No DMARC (TXT)",
                data=no_dmarc_txt,
                file_name="no_dmarc_domains.txt",
                mime="text/plain"
            )

        with tab2:
            st.subheader(f"DMARC p=none Records ({len(dmarc_none_df)})")
            st.dataframe(dmarc_none_df[["domain", "record"]], use_container_width=True)
            
            # Download TXT button
            dmarc_none_txt = "\n".join(dmarc_none_df["domain"].tolist())
            st.download_button(
                label="📥 Download p=none (TXT)",
                data=dmarc_none_txt,
                file_name="dmarc_none_domains.txt",
                mime="text/plain"
            )

        with tab3:
            st.subheader("All Results")
            st.dataframe(df_results, use_container_width=True)
            
            # CSV Download for full report
            csv_buffer = io.StringIO()
            df_results.to_csv(csv_buffer, index=False)
            st.download_button(
                label="📥 Download Full Report (CSV)",
                data=csv_buffer.getvalue(),
                file_name="all_dmarc_results.csv",
                mime="text/csv"
            )