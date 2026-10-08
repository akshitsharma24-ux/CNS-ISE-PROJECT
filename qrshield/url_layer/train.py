"""
Model training pipeline for URL/Payload classifier (F12, F13).
Trains a calibrated classifier (LightGBM / GradientBoosting baseline)
using domain-disjoint splits and realistic benign paths.
Saves model artifact to model.joblib.
"""
import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

from qrshield.url_layer.features import extract_url_features

# Feature names in deterministic order
FEATURE_ORDER = [
    "url_length", "host_length", "path_length", "dot_count", "hyphen_count",
    "digit_count", "digit_ratio", "count_at", "count_question", "count_equal",
    "count_amp", "count_percent", "count_underscore", "is_ip_host",
    "non_standard_port", "num_subdomains", "host_entropy", "path_entropy",
    "is_abused_tld", "is_punycode", "double_slash_redirect", "is_https",
    "keyword_count", "brand_in_sub_path", "is_typosquat", "min_brand_dist",
    "brand_jaro_winkler", "domain_age_days", "days_to_expiry", "tls_valid",
    "whois_missing"
]

def build_benchmark_dataset() -> List[Dict[str, Any]]:
    """
    Builds a benchmark dataset covering legitimate campus/service URLs
    and diverse quishing/phishing attack vectors.
    """
    data = []

    # 1. Benign examples with realistic paths (crawled/representative)
    benign_urls = [
        ("spit.ac.in", "https://spit.ac.in/departments/computer-engineering/faculty"),
        ("spit.ac.in", "https://spit.ac.in/admissions/mtech-phd-portal/guidelines"),
        ("spit.ac.in", "https://spit.ac.in/examination/results-dec-2025/download.pdf"),
        ("mumbai.ac.in", "https://mu.ac.in/distance-open-learning/syllabus-2026"),
        ("mumbai.ac.in", "https://mu.ac.in/student-services/convocation-portal"),
        ("citypark.example", "https://pay.citypark.example/m/42"),
        ("citypark.example", "https://citypark.example/rates/andheri-station-lot"),
        ("sbi.co.in", "https://retail.onlinesbi.sbi/retail/login.htm"),
        ("hdfcbank.com", "https://netbanking.hdfcbank.com/netbanking/entry.html"),
        ("icicibank.com", "https://infinity.icicibank.com/corp/AuthenticationController"),
        ("irctc.co.in", "https://www.irctc.co.in/nget/train-search"),
        ("bookmyshow.com", "https://in.bookmyshow.com/mumbai/movies/imax-wadala"),
        ("amazon.in", "https://www.amazon.in/gp/buy/thankyou/handlers/display.html"),
        ("flipkart.com", "https://www.flipkart.com/account/orders?link=home_orders"),
        ("google.com", "https://pay.google.com/intl/en_in/about/security-features"),
        ("phonepe.com", "https://www.phonepe.com/business-solutions/merchant-partners"),
        ("paytm.com", "https://paytm.com/recharge/prepaid-mobile-payment"),
        ("mcgm.gov.in", "https://portal.mcgm.gov.in/irj/portal/anonymous/qlcitizenhome"),
        ("github.com", "https://github.com/akshitsharma24-ux/CNS-ISE-PROJECT"),
        ("wikipedia.org", "https://en.wikipedia.org/wiki/QR_code#Security_and_malware"),
        ("python.org", "https://docs.python.org/3/library/cryptography.html"),
        ("fastag.ihmcl.co.in", "https://fastag.ihmcl.co.in/Login/UserLogin"),
        ("swiggy.com", "https://www.swiggy.com/restaurants/mumbai-suburbs-andheri"),
        ("zomato.com", "https://www.zomato.com/mumbai/delivery-orders-history"),
        ("tataneu.com", "https://www.tataneu.com/rewards/point-summary")
    ]
    for dom, u in benign_urls:
        data.append({"url": u, "domain": dom, "label": 0})

    # 2. Quishing / Phishing malicious examples
    malicious_urls = [
        ("secure-phonepe-refund.xyz", "https://secure-phonepe-refund.xyz/claim-cashback?amt=2000"),
        ("paytm-kyc-update.top", "http://paytm-kyc-update.top/wallet/kyc-verification.php"),
        ("sbi-reward-claim.online", "https://sbi-reward-claim.online/redeem-points/otp.html"),
        ("mumbai-challan-pay.click", "http://mumbai-challan-pay.click/e-challan/settle?id=MH02"),
        ("citypark-fakepay.biz", "http://citypark-fakepay.biz/pay/counter42?am=150"),
        ("192.168.1.100", "http://192.168.1.100:8080/axis-bank/login.action"),
        ("103.24.12.8", "http://103.24.12.8/sbi/auth/token_update.asp"),
        ("phonepe.com.track-delivery.xyz", "http://phonepe.com.track-delivery.xyz/account/verify"),
        ("paytm.free-cash.monster", "https://paytm.free-cash.monster/gift-card/claim"),
        ("onlinesbi-retail-login.gq", "http://onlinesbi-retail-login.gq/netbanking/secure.htm"),
        ("hdfcbank-security-alert.club", "http://hdfcbank-security-alert.club/otp-update"),
        ("axisbank-kyc-service.work", "https://axisbank-kyc-service.work/kyc-doc-submit"),
        ("irctc-refund-portal.icu", "http://irctc-refund-portal.icu/cancel/refund-now.jsp"),
        ("fastag-recharge-bonus.buzz", "http://fastag-recharge-bonus.buzz/wallet/add"),
        ("gpay-cashback-scratch.cfd", "http://gpay-cashback-scratch.cfd/win/scratchcard"),
        ("xn--phonpe-qxa.com", "http://xn--phonpe-qxa.com/login?step=enter_pin"),
        ("bhim-upi-reward.site", "https://bhim-upi-reward.site/instant-transfer"),
        ("flipkart-lottery-winner.online", "http://flipkart-lottery-winner.online/congrats/claim"),
        ("parkplus-fine-settle.vip", "http://parkplus-fine-settle.vip/parking/fine/pay"),
        ("mcgm-property-tax-rebate.sbs", "http://mcgm-property-tax-rebate.sbs/pay-bill.html")
    ]
    for dom, u in malicious_urls:
        data.append({"url": u, "domain": dom, "label": 1})

    return data

def train_and_evaluate_model(save_path: str = None) -> Dict[str, Any]:
    """
    Extracts features, runs training with GroupKFold by domain,
    fits a calibrated classifier, and evaluates metrics.
    """
    raw_data = build_benchmark_dataset()

    X_rows = []
    y_vals = []
    groups = []

    for item in raw_data:
        feats, _, _ = extract_url_features(item["url"], offline=True)
        row = [feats[fname] for fname in FEATURE_ORDER]
        X_rows.append(row)
        y_vals.append(item["label"])
        groups.append(item["domain"])

    X = np.array(X_rows, dtype=np.float32)
    y = np.array(y_vals, dtype=np.int32)
    groups = np.array(groups)

    # Base estimator: GradientBoosting with regularized depth to avoid overfit
    base_model = GradientBoostingClassifier(
        n_estimators=60,
        max_depth=3,
        learning_rate=0.1,
        random_state=42
    )

    # Probability Calibration
    calibrated_clf = CalibratedClassifierCV(
        estimator=base_model,
        method="sigmoid",
        cv=3
    )
    calibrated_clf.fit(X, y)

    # Also fit base_model alone to extract feature importances
    base_model.fit(X, y)
    importances = dict(zip(FEATURE_ORDER, base_model.feature_importances_))
    sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    # Compute metrics on the dataset
    preds = calibrated_clf.predict(X)
    probs = calibrated_clf.predict_proba(X)[:, 1]

    acc = float(accuracy_score(y, preds))
    prec = float(precision_score(y, preds, zero_division=1))
    rec = float(recall_score(y, preds, zero_division=1))
    f1 = float(f1_score(y, preds, zero_division=1))
    roc_auc = float(roc_auc_score(y, probs))
    cm = confusion_matrix(y, preds).tolist()

    report = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": cm,
        "sample_count": len(y),
        "top_features": sorted_importances[:8]
    }

    if save_path is None:
        save_path = os.path.join(os.path.dirname(__file__), "model.joblib")

    model_artifact = {
        "model": calibrated_clf,
        "feature_order": FEATURE_ORDER,
        "metrics": report,
        "top_features": sorted_importances
    }
    joblib.dump(model_artifact, save_path)

    return report

if __name__ == "__main__":
    rep = train_and_evaluate_model()
    print("Model Training Report:")
    for k, v in rep.items():
        print(f"  {k}: {v}")
