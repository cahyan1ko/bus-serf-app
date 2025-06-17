from app import db
from datetime import datetime

class DeviceHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    device_os = db.Column(db.String(100), nullable=False)
    device_id = db.Column(db.String(100), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'device_name': self.device_name,
            'device_os': self.device_os,
            'device_id': self.device_id,
            'login_time': self.login_time.isoformat(),
        }
