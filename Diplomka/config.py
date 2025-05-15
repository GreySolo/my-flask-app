class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/diplomka'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'logrey'
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    SCHEDULER_API_ENABLED = True
