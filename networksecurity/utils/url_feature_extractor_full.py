import re
import socket
import ssl
import sys
import whois
import requests
import dns.resolver

from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup


SHORTENING_SERVICES = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|short\.io|rebrand\.ly"


class URLFeatureExtractor:

    def __init__(self, url):

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self.url = url
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc.split(":")[0]  # strip port if present

        try:
            self.response = requests.get(url, timeout=7, allow_redirects=True)
            self.soup = BeautifulSoup(self.response.text, "html.parser")
            self.final_url = self.response.url
            self.status_code = self.response.status_code
        except Exception:
            self.response = None
            self.soup = BeautifulSoup("", "html.parser")
            self.final_url = url
            self.status_code = None

    # ── URL Structure ──────────────────────────────────────────────

    def having_ip_address(self):
        """Returns -1 if URL contains an IP address, else 1."""
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])',
            self.url
        )
        return -1 if match else 1

    def url_length(self):
        """Returns 1 if <54 chars, 0 if 54-75, -1 if >75."""
        length = len(self.url)
        if length < 54:
            return 1
        elif length <= 75:
            return 0
        return -1

    def shortening_service(self):
        """Returns -1 if URL uses a shortening service, else 1."""
        return -1 if re.search(SHORTENING_SERVICES, self.url, re.I) else 1

    def having_at_symbol(self):
        """Returns -1 if '@' is in URL (redirects browser), else 1."""
        return -1 if "@" in self.url else 1

    def double_slash_redirecting(self):
        """Returns -1 if '//' appears after position 7 (after https://), else 1."""
        pos = self.url.find("//", 7)
        return -1 if pos > 0 else 1

    def prefix_suffix(self):
        """Returns -1 if '-' in domain (common phishing trick), else 1."""
        return -1 if "-" in self.domain else 1

    def having_sub_domain(self):
        """1 if single subdomain, 0 if two, -1 if more."""
        # Remove www as it's standard
        domain_clean = self.domain
        if domain_clean.startswith("www."):
            domain_clean = domain_clean[4:]
        dots = domain_clean.count(".")
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        return -1

    def https_token(self):
        """Returns -1 if 'https' appears in the domain part of the URL (deceptive), else 1."""
        return -1 if "https" in self.domain.lower() else 1

    # ── SSL + Domain ───────────────────────────────────────────────

    def ssl_final_state(self):
        """Returns 1 if valid SSL certificate, else -1."""
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(
                socket.socket(), server_hostname=self.domain
            ) as s:
                s.settimeout(5)
                s.connect((self.domain, 443))
            return 1
        except Exception:
            return -1

    def domain_registration_length(self):
        """Returns 1 if domain expiry > 1 year away, else -1."""
        try:
            w = whois.whois(self.domain)
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if expiration:
                delta = (expiration - datetime.now()).days
                return 1 if delta > 365 else -1
            return -1
        except Exception:
            return -1

    def age_of_domain(self):
        """Returns 1 if domain older than 6 months, else -1."""
        try:
            w = whois.whois(self.domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age_days = (datetime.now() - creation).days
                return 1 if age_days > 180 else -1
            return -1
        except Exception:
            return -1

    def dns_record(self):
        """Returns 1 if DNS A record exists, else -1."""
        try:
            dns.resolver.resolve(self.domain, "A")
            return 1
        except Exception:
            return -1

    def port(self):
        """Returns -1 if a non-standard port is used, else 1."""
        port = self.parsed.port
        if port is None:
            return 1
        # Standard ports are fine
        return 1 if port in (80, 443) else -1

    # ── HTML Page Features ─────────────────────────────────────────

    def favicon(self):
        """Returns -1 if favicon is loaded from external domain, else 1."""
        if not self.soup:
            return 1
        icon_link = self.soup.find("link", rel=lambda r: r and "icon" in r)
        if icon_link and icon_link.get("href"):
            href = icon_link["href"]
            if href.startswith("http") and self.domain not in href:
                return -1
        return 1

    def request_url(self):
        """Returns -1 if >61% of page objects loaded from external domains."""
        if not self.soup:
            return 1
        total, external = 0, 0
        tags = self.soup.find_all(["img", "script", "link"], src=True) + \
               self.soup.find_all("link", href=True)
        for tag in tags:
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith("http"):
                total += 1
                if self.domain not in src:
                    external += 1
        if total == 0:
            return 1
        ratio = external / total
        if ratio < 0.22:
            return 1
        elif ratio < 0.61:
            return 0
        return -1

    def url_of_anchor(self):
        """Returns -1 if >67% of anchor href links point to external/empty domains."""
        if not self.soup:
            return 1
        anchors = self.soup.find_all("a", href=True)
        total = len(anchors)
        if total == 0:
            return 1
        unsafe = sum(
            1 for a in anchors
            if a["href"].startswith("#") or
               (a["href"].startswith("http") and self.domain not in a["href"])
        )
        ratio = unsafe / total
        if ratio < 0.31:
            return 1
        elif ratio < 0.67:
            return 0
        return -1

    def links_in_tags(self):
        """Returns -1 if many <meta>/<script>/<link> tags point to external domains."""
        if not self.soup:
            return 1
        tags = self.soup.find_all(["meta", "script", "link"])
        total = len(tags)
        if total == 0:
            return 1
        external = sum(
            1 for t in tags
            if (t.get("src") or t.get("href") or "").startswith("http")
            and self.domain not in (t.get("src") or t.get("href") or "")
        )
        ratio = external / total
        if ratio < 0.17:
            return 1
        elif ratio < 0.81:
            return 0
        return -1

    def sfh(self):
        """Server Form Handler: -1 if forms submit to 'about:blank' or external domain."""
        if not self.soup:
            return 1
        forms = self.soup.find_all("form", action=True)
        for form in forms:
            action = form["action"].strip()
            if action in ("", "about:blank"):
                return -1
            if action.startswith("http") and self.domain not in action:
                return 0
        return 1

    def submitting_to_email(self):
        """Returns -1 if form uses 'mailto:' action."""
        if not self.soup:
            return 1
        forms = self.soup.find_all("form", action=True)
        for form in forms:
            if "mailto:" in form["action"].lower():
                return -1
        return 1

    def abnormal_url(self):
        """Returns -1 if WHOIS hostname doesn't match URL domain."""
        try:
            w = whois.whois(self.domain)
            if w.domain_name:
                whois_domain = w.domain_name
                if isinstance(whois_domain, list):
                    whois_domain = whois_domain[0]
                if whois_domain.lower() in self.domain.lower():
                    return 1
            return -1
        except Exception:
            return -1

    def redirect(self):
        """Returns -1 if page redirects more than once."""
        if self.response is None:
            return 0
        redirect_count = len(self.response.history)
        if redirect_count <= 1:
            return 1
        elif redirect_count <= 2:
            return 0
        return -1

    def on_mouseover(self):
        """Returns -1 if JavaScript changes status bar on mouseover."""
        if not self.soup:
            return 1
        page_text = str(self.soup)
        return -1 if "onmouseover" in page_text.lower() else 1

    def right_click(self):
        """Returns -1 if right-click is disabled via JavaScript."""
        if not self.soup:
            return 1
        page_text = str(self.soup)
        return -1 if "contextmenu" in page_text.lower() or "event.button==2" in page_text else 1

    def popup_window(self):
        """Returns -1 if page uses popup windows with text fields."""
        if not self.soup:
            return 1
        page_text = str(self.soup)
        return -1 if "window.open" in page_text else 1

    def iframe(self):
        """Returns -1 if iframe tag is present (often used in clickjacking)."""
        if not self.soup:
            return 1
        return -1 if self.soup.find("iframe") else 1

    # ── External/Stat Features (require 3rd party APIs) ──────────

    def web_traffic(self):
        """Placeholder: returns 0 (requires Alexa/SimilarWeb API)."""
        return 0

    def page_rank(self):
        """Placeholder: returns 0 (requires external PageRank API)."""
        return 0

    def google_index(self):
        """Returns 1 if domain appears indexed (simple heuristic via response)."""
        # Without Google Search API, we check if the site itself responds OK
        if self.response and self.response.status_code == 200:
            return 1
        return -1

    def links_pointing_to_page(self):
        """Placeholder: returns 0 (requires backlink API)."""
        return 0

    def statistical_report(self):
        """Returns -1 if domain matches known phishing TLDs/patterns, else 1."""
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]
        for tld in suspicious_tlds:
            if self.domain.endswith(tld):
                return -1
        return 1


# ── Main extraction function ──────────────────────────────────────

def extract_all_features(url: str) -> dict:
    """
    Extract all 30 phishing detection features from a URL.
    Returns a dict matching the model's expected training columns.
    """
    e = URLFeatureExtractor(url)

    return {
        "having_IP_Address":          e.having_ip_address(),
        "URL_Length":                  e.url_length(),
        "Shortining_Service":          e.shortening_service(),
        "having_At_Symbol":            e.having_at_symbol(),
        "double_slash_redirecting":    e.double_slash_redirecting(),
        "Prefix_Suffix":               e.prefix_suffix(),
        "having_Sub_Domain":           e.having_sub_domain(),
        "SSLfinal_State":              e.ssl_final_state(),
        "Domain_registeration_length": e.domain_registration_length(),
        "Favicon":                     e.favicon(),
        "port":                        e.port(),
        "HTTPS_token":                 e.https_token(),
        "Request_URL":                 e.request_url(),
        "URL_of_Anchor":               e.url_of_anchor(),
        "Links_in_tags":               e.links_in_tags(),
        "SFH":                         e.sfh(),
        "Submitting_to_email":         e.submitting_to_email(),
        "Abnormal_URL":                e.abnormal_url(),
        "Redirect":                    e.redirect(),
        "on_mouseover":                e.on_mouseover(),
        "RightClick":                  e.right_click(),
        "popUpWidnow":                 e.popup_window(),
        "Iframe":                      e.iframe(),
        "age_of_domain":               e.age_of_domain(),
        "DNSRecord":                   e.dns_record(),
        "web_traffic":                 e.web_traffic(),
        "Page_Rank":                   e.page_rank(),
        "Google_Index":                e.google_index(),
        "Links_pointing_to_page":      e.links_pointing_to_page(),
        "Statistical_report":          e.statistical_report(),
    }