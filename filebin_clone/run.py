from backend import create_app, db
from backend.models import Bin
from datetime import datetime, timedelta, timezone
import os

UPLOAD_DIR = os.path.join(os.getcwd(), 'uploads')
app = create_app()

@app.before_request
def cleanup_bins():
    # ⚠️ Run only if DB is ready
    if not db.session:
        return

    expiration_threshold = datetime.now(timezone.utc) - timedelta(days=1)
    expired_bins = Bin.query.filter(Bin.created_at < expiration_threshold).all()

    for bin in expired_bins:
        bin_path = os.path.join(UPLOAD_DIR, bin.bin_id)
        if os.path.exists(bin_path):
            for f in os.listdir(bin_path):
                os.remove(os.path.join(bin_path, f))
            os.rmdir(bin_path)
        db.session.delete(bin)

    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
