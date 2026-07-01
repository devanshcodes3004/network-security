import streamlit as st
import pandas as pd
import os

from urllib.parse import urlparse

from networksecurity.utils.main_utils.utils import load_object
from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.url_feature_extractor_full import extract_all_features


# ── Feature column order MUST match training dataset exactly ─────────
EXPECTED_COLUMNS = [
    "having_IP_Address","URL_Length","Shortining_Service",
    "having_At_Symbol","double_slash_redirecting","Prefix_Suffix",
    "having_Sub_Domain","SSLfinal_State","Domain_registeration_length",
    "Favicon","port","HTTPS_token","Request_URL","URL_of_Anchor",
    "Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
    "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe",
    "age_of_domain","DNSRecord","web_traffic","Page_Rank",
    "Google_Index","Links_pointing_to_page","Statistical_report"
]


# ── Cache model loading for performance ─────────────────────────────
@st.cache_resource
def load_models():

    BASE_DIR = os.path.dirname(__file__)

    preprocessor_path = os.path.join(
        BASE_DIR,
        "final_model",
        "preprocessor.pkl"
    )

    model_path = os.path.join(
        BASE_DIR,
        "final_model",
        "model.pkl"
    )

    preprocessor = load_object(preprocessor_path)

    model = load_object(model_path)

    network_model = NetworkModel(
        preprocessor=preprocessor,
        model=model
    )

    return network_model


# ── Streamlit page configuration ───────────────────────────────────
st.set_page_config(
    page_title="Network Security Threat Detector",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Security Threat Detector")

st.write(
    "Enter a website URL to detect whether it is **Legitimate**, "
    "**Suspicious**, or **Phishing**."
)


# ── URL input box ─────────────────────────────────────────────────
url_input = st.text_input(
    "Enter URL",
    placeholder="https://example.com"
)


# ── Prediction button logic ───────────────────────────────────────
if st.button("🔍 Analyze URL"):

    if not url_input.strip():

        st.warning("Please enter a URL")

        st.stop()


    url = url_input.strip()


    # Automatically add HTTPS if missing
    if not url.startswith(("http://", "https://")):

        url = "https://" + url


    # Validate URL safely (without validators package)
    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:

        st.error("Invalid URL format")

        st.stop()


    # ── Extract phishing features ───────────────────────────────
    with st.spinner("Extracting security features..."):

        try:

            features = extract_all_features(url)

        except Exception as e:

            st.error(f"Feature extraction failed: {e}")

            st.stop()


    # Ensure all expected columns exist
    for col in EXPECTED_COLUMNS:

        if col not in features:

            features[col] = 0


    df = pd.DataFrame([features])[EXPECTED_COLUMNS]


    # ── Load ML model and predict ───────────────────────────────
    with st.spinner("Running ML prediction..."):

        try:

            network_model = load_models()

            prediction = network_model.predict(df)[0]

        except Exception as e:

            st.error(f"Prediction failed: {e}")

            st.stop()


    st.divider()

    st.subheader("Prediction Result")


    # Adjust these labels if your dataset uses different mapping
    if prediction == 1:

        st.success("✅ Legitimate Website")

    elif prediction == 0:

        st.warning("⚠️ Suspicious Website")

    else:

        st.error("🚨 Phishing Website Detected")


    st.divider()


    # ── Show extracted features table ───────────────────────────
    st.subheader("Extracted Feature Values")

    feature_table = pd.DataFrame({

        "Feature": EXPECTED_COLUMNS,

        "Value": [features[col] for col in EXPECTED_COLUMNS]

    })

    st.dataframe(
        feature_table,
        use_container_width=True
    )