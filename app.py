import streamlit as st
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import re

st.set_page_config(page_title="DMARC Live Inspector", layout="wide", page_icon="🛡️")

st.title("🛡️ Accurate DMARC Policy Analyzer")
st.caption("Filters by domain behind the scenes, but returns your original email/fname format in the results!")

# DNS resolver setup
def get_resolver():
    res = dns.resolver.Resolver()
    res.timeout = 3.0
    res.lifetime = 3.0
    res.nameservers = ['8.8.8.8', '1.1.1.1']
    return res

resolver = get_resolver()

def extract_clean_domain(raw_text):
    text = raw_text.strip().lower()
    
    # @ irundha username/fname kalatitu domain mattum edukkum
    if "@" in text:
        text = text.split("@")[-1]
    
    # http, https, paths, www strip pannum
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
            record = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
            raw_txt_records.append(record)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"original": original_line, "domain": domain, "
