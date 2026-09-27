import base64
import io
import json
import sqlite3
import traceback
import bcrypt
import pyotp
import qrcode
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

app = FastAPI(title="MFA Dynamic Flow Demo")

RP_ID = "localhost"
RP_NAME = "MFA Demo System"
ORIGIN = "http://localhost:8000"
DB_FILE = "mfa_users.db"

SESSIONS = {}

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL,
            totp_secret TEXT,
            otp_enabled INTEGER DEFAULT 0,
            webauthn_credentials TEXT DEFAULT '[]',
            failed_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def get_home():
    return FileResponse("static/index.html")

# ==========================================
# 1. ĐĂNG KÝ
# ==========================================

class PreRegisterRequest(BaseModel):
    username: str
    password: str

@app.post("/api/register/check")
def register_check(data: PreRegisterRequest):
    username = data.username.strip()
    if not username or not data.password:
        raise HTTPException(status_code=400, detail="Vui lòng nhập đủ username và password!")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Tên đăng nhập đã tồn tại!")
    conn.close()

    SESSIONS[f"reg_data_{username}"] = {"password": data.password}
    return {"status": "success", "message": "Thông tin hợp lệ. Tiếp tục đăng ký Passkey."}

@app.get("/api/register/passkey-options")
def register_passkey_options(username: str):
    try:
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=username.encode('utf-8'),
            user_name=username,
            user_display_name=username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )
        SESSIONS[f"reg_challenge_{username}"] = options.challenge
        # Parse về dict để FastAPI trả JSON object chuẩn, tránh lỗi double json string
        return json.loads(options_to_json(options))
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Lỗi tạo Passkey options: {str(e)}")

class FinalRegisterRequest(BaseModel):
    username: str
    enable_otp: bool
    credential: dict

@app.post("/api/register/finalize")
def finalize_registration(data: FinalRegisterRequest):
    try:
        temp_data = SESSIONS.get(f"reg_data_{data.username}")
        expected_challenge = SESSIONS.get(f"reg_challenge_{data.username}")

        if not temp_data or not expected_challenge:
            raise HTTPException(status_code=400, detail="Phiên đăng ký đã hết hạn, vui lòng thử lại!")

        verification = verify_registration_response(
            credential=data.credential,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True
        )

        creds = [{
            "id": base64.b64encode(verification.credential_id).decode('utf-8'),
            "public_key": base64.b64encode(verification.credential_public_key).decode('utf-8'),
            "sign_count": verification.sign_count
        }]

        totp_secret = pyotp.random_base32() if data.enable_otp else None
        otp_enabled_val = 1 if data.enable_otp else 0
        pw_hash = bcrypt.hashpw(temp_data["password"].encode('utf-8'), bcrypt.gensalt())

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, password_hash, totp_secret, otp_enabled, webauthn_credentials, failed_attempts, is_locked)
            VALUES (?, ?, ?, ?, ?, 0, 0)
        """, (data.username, pw_hash, totp_secret, otp_enabled_val, json.dumps(creds)))
        conn.commit()
        conn.close()

        SESSIONS.pop(f"reg_data_{data.username}", None)
        SESSIONS.pop(f"reg_challenge_{data.username}", None)

        return {"status": "success", "message": "Tạo tài khoản thành công cùng Passkey bảo mật!"}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Lỗi hoàn tất đăng ký: {str(e)}")

# ==========================================
# 2. ĐĂNG NHẬP & RISK-BASED MFA
# ==========================================

class LoginPasswordRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login/step1-password")
def login_step1(data: LoginPasswordRequest):
    username = data.username.strip()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="Tài khoản không tồn tại!")

    if user["is_locked"] == 1 or user["failed_attempts"] >= 5:
        cur.execute("UPDATE users SET is_locked = 1 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=403, detail="Tài khoản đã bị KHÓA do nhập sai mật khẩu quá 5 lần!")

    is_pw_correct = bcrypt.checkpw(data.password.encode('utf-8'), user["password_hash"])

    if not is_pw_correct:
        new_attempts = user["failed_attempts"] + 1
        is_locked_now = 1 if new_attempts >= 5 else 0
        cur.execute("UPDATE users SET failed_attempts = ?, is_locked = ? WHERE username = ?", 
                    (new_attempts, is_locked_now, username))
        conn.commit()
        conn.close()

        remain = 5 - new_attempts
        if remain <= 0:
            raise HTTPException(status_code=403, detail="Nhập sai 5 lần. Tài khoản đã bị KHÓA!")
        raise HTTPException(status_code=401, detail=f"Sai mật khẩu! Bạn còn {remain} lần thử.")

    failed_count = user["failed_attempts"]
    otp_enabled = bool(user["otp_enabled"])
    is_high_risk = (failed_count == 4)

    cur.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    SESSIONS[f"login_session_{username}"] = {
        "verified_password": True,
        "is_high_risk": is_high_risk,
        "otp_enabled": otp_enabled,
        "qr_served": False
    }

    return {
        "status": "success",
        "username": username,
        "is_high_risk": is_high_risk,
        "otp_enabled": otp_enabled,
        "message": "Mật khẩu chính xác."
    }

@app.get("/api/login/get-otp-qr")
def get_login_otp_qr(username: str):
    session = SESSIONS.get(f"login_session_{username}")
    if not session or not session.get("verified_password"):
        raise HTTPException(status_code=403, detail="Chưa xác thực mật khẩu!")

    if session.get("qr_served"):
        raise HTTPException(status_code=400, detail="Mã QR chỉ được cấp một lần duy nhất cho mỗi phiên!")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT totp_secret, otp_enabled FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản!")

    secret = row["totp_secret"]

    # XỬ LÝ CA KHÔNG CÓ OTP: Nếu chưa từng bật OTP mà rơi vào ca rủi ro cao (High-Risk)
    # Tự động cấp một Secret TOTP mới và lưu vào DB luôn
    if not secret:
        secret = pyotp.random_base32()
        cur.execute("UPDATE users SET totp_secret = ?, otp_enabled = 1 WHERE username = ?", (secret, username))
        conn.commit()

    conn.close()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=f"{username}@demo.local", issuer_name=RP_NAME)

    qr = qrcode.make(uri)
    img_byte_arr = io.BytesIO()
    qr.save(img_byte_arr, format='PNG')
    b64_qr = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')

    session["qr_served"] = True

    return {"secret": secret, "qr_code_base64": f"data:image/png;base64,{b64_qr}"}

class VerifyOtpRequest(BaseModel):
    username: str
    otp: str

@app.post("/api/login/verify-otp")
def verify_login_otp(data: VerifyOtpRequest):
    session = SESSIONS.get(f"login_session_{data.username}")
    if not session or not session.get("verified_password"):
        raise HTTPException(status_code=403, detail="Chưa xác thực mật khẩu!")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT totp_secret FROM users WHERE username = ?", (data.username,))
    row = cur.fetchone()
    conn.close()

    totp = pyotp.TOTP(row["totp_secret"])
    if not totp.verify(data.otp, valid_window=1):
        raise HTTPException(status_code=401, detail="Mã OTP không chính xác hoặc đã hết hạn!")

    return {
        "status": "success",
        "is_high_risk": session["is_high_risk"],
        "message": "Xác thực OTP thành công!"
    }

@app.get("/api/login/passkey-options")
def get_login_passkey_options(username: str):
    session = SESSIONS.get(f"login_session_{username}")
    if not session or not session.get("verified_password"):
        raise HTTPException(status_code=403, detail="Chưa xác thực mật khẩu!")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT webauthn_credentials FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    creds = json.loads(row["webauthn_credentials"]) if row else []
    allowed = [PublicKeyCredentialDescriptor(id=base64.b64decode(c["id"])) for c in creds]
    
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.REQUIRED
    )
    SESSIONS[f"auth_challenge_{username}"] = options.challenge
    return json.loads(options_to_json(options))

class VerifyPasskeyRequest(BaseModel):
    username: str
    credential: dict

@app.post("/api/login/verify-passkey")
def verify_login_passkey(data: VerifyPasskeyRequest):
    session = SESSIONS.get(f"login_session_{data.username}")
    expected_challenge = SESSIONS.get(f"auth_challenge_{data.username}")

    if not session or not expected_challenge:
        raise HTTPException(status_code=400, detail="Không tìm thấy challenge phiên!")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT webauthn_credentials FROM users WHERE username = ?", (data.username,))
    row = cur.fetchone()
    creds = json.loads(row["webauthn_credentials"]) if row else []

    cred_id_bytes = base64url_to_bytes(data.credential["id"])
    matched = next((c for c in creds if base64.b64decode(c["id"]) == cred_id_bytes), None)
    if not matched:
        conn.close()
        raise HTTPException(status_code=404, detail="Không tìm thấy Passkey!")

    verification = verify_authentication_response(
        credential=data.credential,
        expected_challenge=expected_challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=base64.b64decode(matched["public_key"]),
        credential_current_sign_count=matched["sign_count"],
        require_user_verification=True
    )

    matched["sign_count"] = verification.new_sign_count
    cur.execute("UPDATE users SET webauthn_credentials = ? WHERE username = ?", (json.dumps(creds), data.username))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "is_high_risk": session["is_high_risk"],
        "message": "Xác thực Passkey thành công!"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)