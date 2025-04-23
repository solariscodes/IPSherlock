from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class SearchLog(db.Model):
    """Model for storing search logs in the same format as the file-based logs."""
    __tablename__ = 'search_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    client_ip = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    query = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, default=200, nullable=False)
    
    def __repr__(self):
        """Return the log entry in the same format as the file-based logs."""
        timestamp_str = self.timestamp.strftime('[%d/%b/%Y %H:%M:%S]')
        return f"{self.client_ip} - - {timestamp_str} \"GET /results?query={self.query} HTTP/1.1\" {self.status_code} -"
    
    @staticmethod
    def from_log_entry(client_ip, query, status_code=200):
        """Create a SearchLog entry from the components."""
        return SearchLog(
            client_ip=client_ip,
            query=query,
            status_code=status_code
        )
