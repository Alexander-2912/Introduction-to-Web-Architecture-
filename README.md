# Introduction-to-Web-Architecture
## Latar Belakang
Website Simple Twitter memungkinkan pengguna untuk berinteraksi dan berbagi informasi dalam format yang mirip. Fitur utama termasuk kemampuan untuk "mengirim" pesan pendek atau "tweet," mengunggah foto, serta melihat daftar tweet terbanyak yang diposting oleh pengguna lain. Dengan fitur unggahan foto, pengguna dapat memperkaya konten yang mereka bagikan, memungkinkan untuk berbagi momen dan pengalaman visual dengan audiens mereka. Selain itu, platform ini juga dilengkapi dengan halaman login dan registrasi yang memungkinkan pengguna untuk membuat akun baru dan masuk ke platform dengan mudah. Dengan kombinasi fitur-fitur ini, pengguna dapat terlibat dalam percakapan, mengekspresikan pikiran mereka, dan membangun interaksi sosial. Ini menciptakan ruang untuk berbagi, berdiskusi, dan terlibat dalam komunitas online yang dinamis.

## Requirements & Objective
Website "Simple Twitter" telah dikembangkan menggunakan Flask untuk backend-nya, sedangkan Vue.js digunakan sebagai kerangka kerja frontend-nya. Teknologi lain yang terlibat dalam pembuatan situs ini termasuk Axios untuk manajemen permintaan HTTP, Pinia untuk pengelolaan state, dan Datatable untuk tampilan data terstruktur. Tujuan utama dari proyek ini adalah menciptakan sebuah platform yang menyerupai Twitter beserta fitur-fiturnya. Melalui pendekatan teknologi seperti Flask dan Vue.js membuat backend yang responsif dan dapat diandalkan, serta tampilan frontend yang dinamis dan ramah pengguna. Integrasi dengan berbagai teknologi ini bertujuan agar pengalaman pengguna menjadi lengkap, memungkinkan mereka untuk mulai menggunakan platform "Simple Twitter" tanpa hambatan teknis yang signifikan.

## Flowchart
[Blank diagram.pdf](https://github.com/Alexander-2912/Introduction-to-Web-Architecture-/files/13228313/Blank.diagram.pdf)
Langkah-langkah flowchart:
1. User masuk ke halaman login
2. Apakah user sudah punya akun?
   2.1. Apabila tidak, user masuk ke halaman registrasi dan membuat akun, kemudian kembali ke langkah 1
   2.2. Apabila ya, user masuk ke langkah 3
3. Masuk ke halaman utama: pada halaman ini, user diberikan dua pilihan
   3.1. User membuat tweet
   3.2. User masuk ke halaman leaderboard
4. User melakukan logout
5. Selesai

## Functions
Dalam projek ini terdapat banyak folder, file, dan code digunakan. Dokumentasi ini akan menjelaskan seluruh code yang digunakan secara singkat.

### Code 1
Code terdapat pada Flask/app/admin/MyCustomModel.py
```
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask import redirect
from flask_admin import AdminIndexView
import os
from dotenv import load_dotenv

load_dotenv()


VUE_BASE_URL = os.getenv("VUE_BASE_URL")
class CustomModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role("admin")
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(f"{VUE_BASE_URL}/login")

class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role("admin")
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(f"{VUE_BASE_URL}/login")
```
Kode yang disediakan adalah bagian dari pengaturan tampilan admin dalam aplikasi web menggunakan kerangka kerja Flask. Pertama, kode mengimpor modul dan pustaka yang diperlukan, seperti ModelView dari flask_admin.contrib.sqla untuk membuat tampilan terkait database, current_user dari flask_login untuk mendapatkan informasi pengguna yang saat ini terotentikasi, dan AdminIndexView dari flask_admin untuk menangani tampilan admin utama. Kode juga memuat variabel lingkungan dari file .env menggunakan load_dotenv() dan mendapatkan nilai URL dasar Vue.js dari variabel lingkungan untuk penggunaan dalam pengalihan halaman.

Kemudian, terdapat dua kelas: CustomModelView dan HomeAdminView. CustomModelView mewarisi ModelView dan memiliki metode is_accessible yang memeriksa apakah pengguna terotentikasi dan memiliki peran "admin". Jika akses ditolak, metode inaccessible_callback akan mengarahkan pengguna kembali ke halaman login menggunakan URL Vue.js yang diambil dari variabel lingkungan. Sementara HomeAdminView mewarisi AdminIndexView dan memiliki metode serupa untuk memeriksa akses pengguna ke tampilan admin utama.

Secara keseluruhan, kode ini bertujuan mengatur kontrol akses terhadap tampilan admin berdasarkan status autentikasi pengguna dan peran yang dimilikinya. Jika pengguna bukan admin atau tidak terotentikasi, mereka akan diarahkan kembali ke halaman login di Vue.js yang telah ditentukan dalam variabel lingkungan.

### Code 2
Code terdapat pada Flask/app/auth/__init__.py
```
from flask import Blueprint
from flask_cors import CORS

authBp = Blueprint('auth', __name__)
CORS(authBp, supports_credentials=True)

from app.auth import routes
```

Kode ini menggambarkan penggunaan Blueprint dalam Flask untuk mengatur rute yang berkaitan dengan otorisasi (auth) dalam aplikasi. Pertama, blueprint 'auth' dibuat menggunakan Blueprint() dari Flask. Blueprint digunakan untuk mengelompokkan rute-rute terkait dalam sebuah modul tertentu. Di sini, 'authBp' merupakan sebuah blueprint yang akan menampung semua rute dan logika terkait otorisasi.

Selanjutnya, flask_cors.CORS digunakan untuk menambahkan aturan CORS (Cross-Origin Resource Sharing) ke blueprint 'auth'. Aturan ini memungkinkan permintaan lintas domain dengan memberikan izin akses melalui mekanisme kredensial, diwakili oleh argumen supports_credentials=True.

Setelah inisialisasi blueprint dan penambahan aturan CORS, kode selanjutnya mengimpor rute-rute terkait otorisasi dari modul app.auth.routes. Dengan demikian, blueprint 'auth' akan terhubung dengan rute-rute yang didefinisikan dalam modul routes di dalam paket app.auth. Hal ini memungkinkan untuk mengelompokkan dan mengatur rute-rute khusus otorisasi terkait dalam aplikasi Flask, memisahkan logika otorisasi dari rute-rute lain untuk meningkatkan keterbacaan dan pemeliharaan kode.

### Code 3
Code terdapat pada Flask/app/auth/routes.py
```
from flask import request, jsonify, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity

from app.extensions import db, jwt
from app.auth import authBp
from app.models.user import Users
from app.models.blacklist_token import BlacklistToken

from flask_login import login_user

@authBp.route("/register", methods=['POST'], strict_slashes =False)
def registration():
    # get data from request json
    data = request.get_json()
    print(data)
    # get username password email from json
    username = data.get('username', None)
    password = generate_password_hash(data.get('password', None))
    email = data.get('email', None)
    role = data.get('role', 'user')
    error = None

    # validasi input
    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required.'
    
    db.session.add(Users(username=username,
                                password=password,
                                email=email, role=role))
    db.session.commit()

    if error:
        return jsonify({"error": error})

    response = make_response(jsonify({
        "success": True,
        "message":"Berhasil Mendaftarkan User",
        }), 200)
    
    return response

@authBp.route("/login", methods=['POST'], strict_slashes = False)
def login():
    data = request.get_json()
    
    username = data.get('username', None)
    password = data.get('password', None)

    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required.'
    
    error = None
    user = Users.query.filter_by(username=username).first()
    if user is None:
        error = "username not found"
    elif not check_password_hash(user.password, password):
        error = "Incorrect password"
    else:
        login_user(user)
        access_token = create_access_token(identity=user.user_id)
        refresh_token = create_refresh_token(identity=user.user_id)
 
    if error:
        return jsonify({"error": error}), 422

    response = make_response(jsonify({
        "success": True,
        "message":"Berhasil Login",
        "access_token" : access_token,
        "refresh_token": refresh_token}), 200)

    return response

@authBp.route('/refresh', methods=['POST'])
@jwt_required(locations=["headers"], refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(access_token), 200

@authBp.route("/logout", methods=['POST'], strict_slashes = False)
@jwt_required(locations=["headers"])
def logout():
    raw_jwt = get_jwt()
    print(raw_jwt)

    jti = raw_jwt.get('jti')
    token = BlacklistToken(jti = jti)
    
    db.session.add(token)
    db.session.commit()

    response = make_response(jsonify({
        "message":"Berhasil Logout"}), 200)
    return response

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = BlacklistToken.query.filter_by(jti=jti).first()
    return token_in_redis is not None
```
Kode yang disediakan bertanggung jawab atas logika otentikasi pengguna dalam sebuah aplikasi web menggunakan Flask. Terdapat beberapa rute yang memungkinkan proses registrasi, login, refresh token, dan logout.

Rute Registrasi (/register):
- Rute ini menangani permintaan POST untuk mendaftarkan pengguna baru.
- Data JSON dari permintaan digunakan untuk mendapatkan informasi seperti username, password (yang di-hash sebelum disimpan), alamat email, dan peran pengguna. Terdapat validasi untuk memastikan bahwa informasi yang diberikan lengkap.
- Jika data valid, pengguna baru ditambahkan ke database dan respons "Berhasil Mendaftarkan User" dikirim.
  
Rute Login (/login):
- Rute ini memproses permintaan POST untuk login pengguna.
- Data JSON dari permintaan digunakan untuk mendapatkan username dan password.
- Terdapat validasi untuk memastikan bahwa informasi login tersedia. Jika username tidak ditemukan atau password tidak cocok, pesan kesalahan yang sesuai dikirim sebagai respons.
- Jika login berhasil, pengguna dianggap terautentikasi, dan token akses serta token refresh diciptakan menggunakan create_access_token dan create_refresh_token dari flask_jwt_extended.
- Respons yang berisi token akses dan token refresh dikirim sebagai hasil dari proses login yang sukses.

Rute Refresh Token (/refresh):
- Rute ini memperbaharui token akses.
- Pengguna yang sudah terotentikasi menggunakan token akses saat ini.
- Token akses baru diciptakan menggunakan create_access_token berdasarkan identitas pengguna.
- Respons yang berisi token akses baru dikirim sebagai hasil dari proses pembaruan token yang sukses.

Rute Logout (/logout):
- Rute ini memproses permintaan POST untuk logout pengguna.
- Token JWT dari permintaan digunakan untuk mendapatkan identitas token.
- Token tersebut ditambahkan ke daftar blacklist untuk mencegah penggunaan kembali.
- Respons "Berhasil Logout" dikirim setelah proses logout berhasil.
- Fungsi check_if_token_is_revoked: Fungsi ini digunakan sebagai loader untuk memeriksa apakah token telah dimasukkan ke dalam daftar blacklist, sehingga memastikan validitas token yang digunakan pada setiap permintaan. Jika token terdaftar dalam daftar blacklist, maka token dianggap dicabut atau tidak valid.

### Code 4
Code terdapat pada Flask/app/frontend/__init__.py
```
from flask import Blueprint
from flask_cors import CORS

frontendBp = Blueprint('frontend', __name__)
CORS(frontendBp)

from app.frontend import routes
```
Kode ini menggunakan Blueprint dalam Flask untuk mengelompokkan rute-rute yang berkaitan dengan tampilan depan (frontend) dari sebuah aplikasi web. Blueprint 'frontend' dibuat menggunakan Blueprint() dari Flask untuk menampung rute-rute yang terkait dengan tampilan depan.

Selanjutnya, flask_cors.CORS digunakan untuk menambahkan aturan CORS (Cross-Origin Resource Sharing) ke blueprint 'frontend'. Ini memungkinkan permintaan lintas domain dengan memberikan izin akses untuk sumber daya pada blueprint ini.

Setelah inisialisasi blueprint dan penambahan aturan CORS, kode kemudian mengimpor rute-rute terkait tampilan depan dari modul app.frontend.routes. Dengan demikian, semua rute yang terdefinisi dalam modul routes di dalam paket app.frontend akan terkait dengan blueprint 'frontend'. Hal ini memungkinkan untuk mengelompokkan rute-rute spesifik tampilan depan ke dalam satu blueprint, memisahkan logika tampilan depan dari bagian lain aplikasi untuk mempermudah pengelolaan dan pemeliharaan kode.

### Code 5
Code terdapat pada Flask/app/frontend/routes.py
```
from flask import render_template
from app.frontend import frontendBp

@frontendBp.route("/login")
def login():
    return render_template('/auth/login.html')

@frontendBp.route("/register")
def register():
    return render_template('/auth/register.html')

@frontendBp.route("/")
def home():
    return render_template('/home/index.html')

@frontendBp.route("/leaderboard")
def leader():
    return render_template('/home/leaderboard.html')
```
Kode ini menangani rute-rute tertentu yang terkait dengan tampilan depan dari suatu aplikasi web menggunakan Flask. Setiap rute yang terdaftar dalam Blueprint 'frontend' diatur untuk menampilkan halaman-halaman tertentu saat diakses.
- Rute '/login':
Rute ini ditujukan untuk menampilkan halaman login. Ketika rute ini diakses, fungsi login() dijalankan, yang kemudian menggunakan render_template dari Flask untuk merender halaman HTML yang berkaitan dengan login, dalam hal ini '/auth/login.html'.
- Rute '/register':
Rute ini mengarah ke halaman registrasi. Fungsi register() merespons dengan memuat halaman HTML terkait registrasi ('/auth/register.html') menggunakan render_template.
Rute '/':
- Rute ini merupakan rute utama atau beranda. Saat diakses, fungsi home() akan merender halaman utama aplikasi, yaitu halaman beranda ('/home/index.html').
Rute '/leaderboard':
Rute ini mengarah ke halaman leaderboard. Fungsi leader() merespons dengan memuat halaman HTML yang menampilkan leaderboard ('/home/leaderboard.html') menggunakan render_template.
Dengan menggunakan Blueprint 'frontend' dan fungsi-fungsi ini, setiap rute terkait tampilan depan aplikasi diarahkan untuk merender halaman HTML yang sesuai ketika rute tersebut diakses oleh pengguna melalui peramban web. Ini memungkinkan navigasi yang jelas antara berbagai bagian dari tampilan depan aplikasi berbasis Flask.

### Code 6
Code terdapat pada Flask/app/models/blacklist_token.py
```
from app.extensions import db

class BlacklistToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)

    def serialize(self): 
        return {
            "id": self.id,
            "jti": self.jti,
        }
```
Kode yang disediakan adalah bagian dari model dalam aplikasi yang menggunakan SQLAlchemy, sebuah ORM (Object-Relational Mapping) untuk Flask, dan kemungkinan besar terkait dengan manajemen token yang terdaftar dalam daftar hitam (blacklist) untuk tujuan keamanan dalam otentikasi.
- Pemodelan Token Hitam (Blacklist Token): Kode ini mendefinisikan model database untuk entitas yang disebut BlacklistToken. Model ini memiliki dua kolom dalam tabel database: id sebagai kunci utama yang merupakan bilangan bulat (Integer) dan jti yang merupakan string unik yang tidak boleh kosong (nullable=False) dengan panjang maksimum 36 karakter (db.String(36)). jti biasanya merujuk pada JWT (JSON Web Token) ID yang digunakan dalam otentikasi.
- Metode Serialize: Terdapat pula sebuah metode serialize() yang digunakan untuk merangkum objek BlacklistToken ke dalam format yang mudah diserialisasi, mungkin untuk keperluan seperti output JSON atau pemrosesan data lainnya. Metode ini mengembalikan objek dalam bentuk dictionary dengan atribut id dan jti.

Model BlacklistToken bertujuan untuk melacak token yang telah dicabut atau ditempatkan dalam daftar hitam, yang biasanya digunakan dalam aplikasi yang menerapkan JWT (JSON Web Token) untuk otentikasi. Saat token ditempatkan dalam daftar hitam, itu berarti token tersebut dianggap tidak valid dan tidak akan diterima saat mencoba mengakses sumber daya atau melakukan otentikasi ulang. Ini bertujuan untuk meningkatkan keamanan dengan menonaktifkan token yang telah dicurigai atau tidak diinginkan.

### Code 7
Code terdapat pada Flask/app/models/count_tweet.py
```
from app.extensions import db

# table database user
class CountTweets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    count_tweet = db.Column(db.Integer, default=0)
    # fungsi serialize untuk mengembalikan data dictionary
    def serialize(self): 
        return {
            "id": self.id,
            "username": self.username,
            "count_tweet":self.count_tweet,
        }
```

Kode yang diberikan adalah bagian dari model dalam aplikasi yang menggunakan SQLAlchemy untuk Flask. Model ini, yang disebut CountTweets, bertujuan untuk menyimpan informasi terkait jumlah tweet yang diposting oleh setiap pengguna dalam aplikasi. Dalam model ini terdapat tiga atribut utama:
- id: Merupakan sebuah kolom yang bertindak sebagai kunci utama (primary key) dalam tabel database dan diatur sebagai bilangan bulat (Integer).
- username: Menyimpan nama pengguna (username) yang merupakan string unik dan tidak boleh kosong (nullable=False). Atribut ini digunakan untuk mengidentifikasi secara unik setiap pengguna.
- count_tweet: Merupakan sebuah kolom yang menunjukkan jumlah tweet yang telah diposting oleh pengguna tersebut. Kolom ini diatur sebagai bilangan bulat (Integer) dengan nilai default 0, menunjukkan bahwa jumlah tweet akan dimulai dari nol ketika pengguna baru pertama kali mendaftar.
Selain atribut-atribut tersebut, model ini juga menyertakan metode serialize(). Metode ini bertujuan untuk memudahkan pengubahan objek CountTweets menjadi format yang lebih mudah diolah, seperti format JSON. Dalam hal ini, metode serialize() mengembalikan objek sebagai dictionary yang berisi nilai dari id, username, dan count_tweet.

### Code 8
Code terdapat pada Flask/app/models/trending.py
```
from app.extensions import db

class Trending(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    count_tweet = db.Column(db.Integer, default=0)
    def serialize(self): 
        return {
            "id": self.id,
            "username": self.username,
            "count_tweet":self.count_tweet,
        }
```
Kode yang diberikan adalah bagian dari model dalam aplikasi Flask yang menggunakan SQLAlchemy, sebuah ORM yang memfasilitasi interaksi dengan database. Model yang disebut Trending ini bertujuan untuk merepresentasikan tabel dalam database yang menyimpan informasi terkait tren atau kecenderungan aktivitas pengguna dalam aplikasi.
Model Trending memiliki beberapa atribut utama yang mencakup:
- id: Sebuah kolom yang berperan sebagai kunci utama (primary key) dalam tabel database. Atribut ini berupa bilangan bulat (Integer).
- username: Merupakan kolom yang menyimpan nama pengguna (username) yang bersifat unik dan tidak boleh kosong (nullable=False). Digunakan untuk mengidentifikasi pengguna secara unik.
- count_tweet: Atribut ini menyimpan jumlah tweet yang telah diposting oleh pengguna tertentu. Kolom ini berjenis bilangan bulat (Integer) dengan nilai default 0, menandakan bahwa jumlah tweet dimulai dari nol ketika pengguna pertama kali mendaftar.
Terkait dengan fungsionalitas, model ini menyediakan metode serialize() yang berfungsi mengonversi objek dari kelas Trending ke dalam format yang lebih mudah diproses, seperti format JSON. Metode serialize() mengembalikan objek sebagai dictionary yang berisi nilai dari id, username, dan count_tweet.

### Code 9
Code terdapat pada Flask/app/models/tweet.py
```
from app.extensions import db

class Tweets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(128))
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    image_name = db.Column(db.String(255), nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    user = db.relationship('Users', backref=db.backref('tweets', lazy=True))

    def serialize(self): 
        return {
            "id": self.id,
            "content": self.content,
            "user_id" : self.user_id,
            "image_name": self.image_name,
            "image_path": self.image_path,
            # "user": self.user.serialize()
        }    
```
Kode yang diberikan merupakan bagian dari model dalam aplikasi Flask yang menggunakan SQLAlchemy, suatu ORM (Object-Relational Mapping) untuk memfasilitasi komunikasi dengan database. Model ini, yang disebut Tweets, dirancang untuk merepresentasikan entitas atau data terkait dengan postingan tweet dalam aplikasi.
Model Tweets memiliki beberapa atribut utama:
- id: Merupakan kolom dalam database yang bertindak sebagai kunci utama (primary key). Tipe datanya adalah bilangan bulat (Integer) yang memberikan pengenal unik untuk setiap entri di tabel.
- content: Kolom ini menyimpan teks dari postingan tweet dengan panjang maksimum 128 karakter.
- user_id: Menyimpan referensi ke pengguna yang memposting tweet ini. Kolom ini merupakan kunci asing (foreign key) yang mengacu ke kolom user_id dalam tabel users.
- image_name dan image_path: Kolom-kolom ini menyimpan informasi terkait gambar yang terlampir dalam postingan tweet, dengan image_name berisi nama berkas gambar dan image_path berisi lokasi penyimpanan gambar tersebut.
Model ini juga memiliki hubungan (relationship) dengan model Users, yang memungkinkan untuk mengakses informasi pengguna terkait dengan setiap tweet yang diposting. Terdapat metode serialize() yang dirancang untuk mengonversi objek dari kelas Tweets ke dalam format yang mudah diolah, seperti format JSON. Metode serialize() mengembalikan objek sebagai dictionary yang memuat nilai-nilai dari atribut-atribut seperti id, content, user_id, image_name, dan image_path.

### Code 10
Code terdapat pada Flask/app/models/user.py
```
from app.extensions import db

class Users(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique = True)
    email = db.Column(db.String(128))
    password = db.Column(db.String(128))
    role = db.Column(db.String(80), nullable=False, server_default='user')

    def has_role(self, role_name):
        return self.role == role_name
    
    @property
    def is_authenticated(self):
        return True if self.user_id is not None else False

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id

    def __unicode__(self):
        return self.username
    

    def serialize(self): 
        return {
            "username": self.username,
            "email": self.email,
            "password": self.password
        }
```
Kode yang diberikan merupakan bagian dari model dalam aplikasi Flask yang menggunakan SQLAlchemy, sebuah ORM (Object-Relational Mapping) yang memfasilitasi interaksi dengan database. Model yang disebut Users ini bertujuan untuk merepresentasikan informasi terkait dengan pengguna (user) dalam aplikasi.
Model Users memiliki beberapa atribut utama yang mencakup:
- user_id: Merupakan sebuah kolom dalam database yang berperan sebagai kunci utama (primary key) untuk mengidentifikasi secara unik setiap entitas pengguna.
- username: Menyimpan nama pengguna (username) yang bersifat unik dan diatur agar tidak terjadi duplikasi (unique = True).
- email: Atribut ini menyimpan alamat surel (email) pengguna.
- password: Merupakan kolom yang digunakan untuk menyimpan kata sandi (password) dari pengguna. Nilainya juga disimpan dalam bentuk string.
- role: Atribut yang menunjukkan peran (role) pengguna dalam aplikasi. Diatur dengan nilai default 'user' jika tidak diatur secara eksplisit.
Selain atribut-atribut tersebut, model Users juga memiliki beberapa metode yang membantu memeriksa status pengguna, seperti:
- has_role(role_name): Memeriksa apakah pengguna memiliki peran tertentu berdasarkan perbandingan nilai atribut role dengan role_name.
- Metode property seperti is_authenticated, is_active, dan is_anonymous digunakan untuk menetapkan properti yang menyediakan informasi otentikasi dan keaktifan pengguna.
- Metode get_id digunakan untuk mengambil nilai user_id sebagai identitas unik pengguna.
Terdapat pula metode serialize() yang bertujuan mengembalikan objek pengguna sebagai dictionary yang memuat informasi dasar seperti username, email, dan password.

### Code 11
Code terdapat pada Flask/app/postCount/postCount.py
```
from app.extensions  import db
from app.models.count_tweet import CountTweets
from app.models.user import Users
from app.models.tweet import Tweets



def count_tweet():
    users = Users.query.all()
    user_posts = {}
    for user in users:
        count_tweet = Tweets.query.filter_by(user_id=user.user_id).count()
        user_posts[user.username] = count_tweet

    sorted_users = sorted(user_posts.items(), key=lambda x: x[1], reverse=True)

    existing_trending_users = CountTweets.query.all()
    existing_users = {trending_user.username: trending_user for trending_user in existing_trending_users}

    for username, count_tweet in sorted_users:
        if username in existing_users:
            trending_user = existing_users[username]
            trending_user.count_tweet = count_tweet
        else:
            trending_user = CountTweets(username=username, count_tweet=count_tweet)
            db.session.add(trending_user)

    db.session.commit()
```
Kode yang diberikan berfungsi untuk melakukan penghitungan jumlah posting tweet yang dilakukan oleh setiap pengguna dalam aplikasi. Langkah-langkah utama yang dilakukan oleh fungsi count_tweet() adalah sebagai berikut:
- Mengambil Data Pengguna dan Jumlah Tweet:
Pertama, kode mengambil daftar semua pengguna dari model Users dengan menggunakan Users.query.all(). Kemudian, melalui pengulangan, kode menghitung jumlah tweet yang diposting oleh setiap pengguna dengan menggunakan Tweets.query.filter_by(user_id=user.user_id).count(), dan menyimpan jumlah tersebut dalam sebuah dictionary user_posts dengan key berupa nama pengguna (username).
- Sort dan Perbarui Data Tren:
Selanjutnya, kode mengurutkan pengguna berdasarkan jumlah tweet yang diposting secara turun dengan fungsi sorted(). Langkah ini membantu menemukan pengguna-pengguna dengan jumlah tweet terbanyak.
- Pembaruan Data Tren:
Kode kemudian memeriksa apakah pengguna-pengguna yang ada telah terdaftar dalam data tren (CountTweets). Jika iya, kode memperbarui jumlah tweet pada entri yang sudah ada. Jika pengguna belum ada dalam data tren, kode membuat entri baru untuk pengguna tersebut dan menyimpannya dalam database.
- Komitmennya ke Database:
Terakhir, setelah melakukan pembaruan data tren, perubahan-perubahan tersebut disimpan dalam database melalui db.session.commit().

### Code 12
```
from flask import request, jsonify, make_response
from app.extensions import db

from app.postCount import countBp
from app.models.count_tweet import CountTweets

from flask_jwt_extended import jwt_required, get_jwt_identity


@countBp.route("", methods=['GET'], strict_slashes = False)
@jwt_required(locations=["headers"],optional=True)
def get_count_tweet():
    limit = request.args.get('limit', 20)
    if type(limit) is not int:
        return jsonify({'message': 'invalid parameter'}), 400
    
    user_id = get_jwt_identity()

    if not user_id:
        user_id = "None"
    else:
        user_id = user_id

    # get tweets by id
    tweets = db.session.execute(
        db.select(CountTweets).limit(limit)
    ).scalars()

    results = []
    for tweet in tweets:
        results.append(tweet.serialize())

    response = make_response(jsonify(
        user_id = user_id,
        data=results
    ), 200)
    # response.headers['Access-Control-Allow-Origin'] = '*'
    return response
```
Fungsi yang diberikan merupakan endpoint dari sebuah Blueprint di Flask yang memproses permintaan GET terkait jumlah posting tweet dari pengguna tertentu. Berikut adalah penjelasan langkah-langkah yang dijalankan oleh fungsi get_count_tweet():
- Menerima Parameter dan Identitas Pengguna:
Fungsi ini menerima permintaan GET dan mengambil parameter limit dari query string. Jika parameter limit tidak bertipe data integer, fungsi akan merespons dengan pesan kesalahan ('invalid parameter') dan status kode 400 (Bad Request).
- Pengidentifikasi Pengguna (User Identity):
Fungsi ini menggunakan Flask-JWT-Extended untuk mengambil identitas pengguna yang terautentikasi dari token JWT yang disertakan dalam permintaan. Jika tidak ada identitas pengguna yang teridentifikasi (user_id tidak ada), maka nilai "None" akan digunakan sebagai nilai identitas pengguna yang akan digunakan untuk pengambilan data tweet.
- Mengambil Data Tweet:
Fungsi menggunakan SQLAlchemy untuk menjalankan query yang mengambil data jumlah tweet dari entitas CountTweets. Query ini menggunakan fungsi limit untuk membatasi jumlah data yang diambil sesuai dengan nilai limit yang telah ditentukan sebelumnya.
- Serialisasi Data dan Pembentukan Respon:
Hasil data tweet yang diperoleh kemudian diubah menjadi format serialisasi melalui iterasi, dan disimpan dalam variabel results. Selanjutnya, hasil serialisasi dan informasi pengguna (user_id) dikemas dalam respons JSON.
- Mengembalikan Respons:
Respons yang terbentuk dikirimkan kembali dalam format JSON dengan status kode 200 (OK). Selain itu, terdapat kode yang kemungkinan di-comment (response.headers['Access-Control-Allow-Origin'] = '*') untuk menetapkan header akses kontrol lintas situs (CORS), yang memungkinkan permintaan dari sumber lintas domain.

### Code 13
Code terdapat pada Flask/app/static/assets/js/script-count.js
```
function get_data() {
    //GET TWEET FROM BACKEND
    let xhr = new XMLHttpRequest();
    let url = "http://127.0.0.1:5000/api/counts"; //ganti nama file sesuai nama file json kalian
    xhr.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {
        let res = JSON.parse(this.response)
        res.data.forEach((count, index) => {
            console.log(count)
            let tbody = document.getElementById("tbody")
            let tr = document.createElement("tr")
            let th_id = document.createElement('th')
            let td_username = document.createElement('td')
            let td_count = document.createElement("td")
            th_id.innerHTML = index + 1
            td_username.innerHTML = count.username
            td_count.innerHTML = count.count_tweet
            tr.append(th_id, td_username, td_count)
            tbody.append(tr)
        });
      }
    }
    xhr.open("GET", url, true);
    xhr.send();
  }
  
  window.onload = function () {
    // cek apakah access_token & 
    if (localStorage.getItem("access_token") == null) {
      const sectionForm = document.getElementById("section-form")
      sectionForm.classList.add("d-none")
    }
    get_data()
  }
```
Fungsi get_data() dan blok kode dalam window.onload adalah bagian dari JavaScript yang bertujuan untuk mengambil data jumlah tweet dari backend menggunakan XMLHttpRequest (XHR) dan menampilkan informasi tersebut dalam tabel di halaman web. Berikut adalah langkah-langkah yang dilakukan oleh kode tersebut:
Fungsi get_data() untuk Mengambil Data dari Backend:
- Fungsi get_data() menggunakan XMLHttpRequest untuk melakukan permintaan GET ke alamat URL tertentu (dalam hal ini "http://127.0.0.1:5000/api/counts").
- Ketika respons diterima (this.readyState == 4 dan this.status == 200), data yang diterima diuraikan dari format JSON menjadi objek JavaScript.
- Untuk setiap entri dalam res.data, sebuah baris (<tr>) dibuat dalam tabel HTML.
- Informasi dari setiap entri (username dan jumlah tweet) disematkan ke dalam elemen tabel (kolom username dan kolom count_tweet) untuk ditampilkan.
Blok window.onload untuk Menjalankan Fungsi saat Halaman Dimuat:
- Blok window.onload mengatur perilaku yang akan dijalankan saat halaman web dimuat sepenuhnya.
- Pertama, blok kode melakukan pemeriksaan apakah token akses (access_token) tersedia dalam penyimpanan lokal browser. Jika tidak ada, bagian formulir pada halaman web diatur menjadi tersembunyi (d-none).
- Setelah itu, fungsi get_data() dijalankan untuk mengambil dan menampilkan data jumlah tweet dari backend saat halaman dimuat.

### Code 14
Code terdapat pada Flask/app/static/assets/js/script-home.js
```
function get_data() {
  //GET TWEET FROM BACKEND
  let xhr = new XMLHttpRequest();
  let url = "http://127.0.0.1:5000/api/tweets"; //ganti nama file sesuai nama file json kalian
  xhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      let tweets = JSON.parse(this.response)
      console.log(tweets)
      tweets["data"].forEach(tweet => {
        const btnLike = document.createElement("span")
        const tweetSection = document.getElementById("section-tweets")
        const card = document.createElement("div")
        card.setAttribute("class", "card mt-3 mb-2")
        const cardHeader = document.createElement("div")
        cardHeader.setAttribute("class", "card-header")
        cardHeader.innerHTML = "Tweet from user " + tweet.user.username
        const cardBody = document.createElement("div")
        cardBody.setAttribute("class", "card-body")
        const blockquote = document.createElement("blockquote")
        blockquote.setAttribute("class", "blockquote mb-2 mt-2")
        const p = document.createElement("p")
        p.innerHTML = tweet.content
        btnLike.setAttribute("class", "badge bg-primary")
        btnLike.innerHTML = "12 Like <i class='bi bi-hand-thumbs-up-fill'></i>"
        // image element 
        if(tweet.image_name && tweet.image_path != null){
          let imgEl = document.createElement("img");
          imgEl.setAttribute("alt", tweet.image_name);
          imgEl.setAttribute("src", tweet.image_path);
          imgEl.setAttribute(
            "class",
            "object-fit-contain w-50 h-100 img-thumbnail"
          );
          imgEl.setAttribute("id", tweet.id);
          blockquote.append(p, imgEl)
        }

        blockquote.append(p, btnLike)
        cardBody.append(blockquote)
        card.append(cardHeader, cardBody)
        tweetSection.append(card)
      });
    }
  }
  xhr.open("GET", url, true);
  xhr.send();
}

window.onload = function () {
  // cek apakah access_token & 
  if (localStorage.getItem("access_token") == null) {
    const sectionForm = document.getElementById("section-form")
    location.href = 'http://127.0.0.1:5173/login'
    sectionForm.classList.add("d-none")
  }
  get_data()
}

setInterval(refresh_token(), 1000)
function refresh_token() {
  let xhr = new XMLHttpRequest();
  let url = "http://127.0.0.1:5000/api/auth/refresh";
  //ganti nama file sesuai nama file json kalian
  xhr.open("POST", url, true)
  xhr.setRequestHeader("Authorization", `Bearer ${localStorage.getItem('access_token')}`);
  xhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      // console.log(this.response)
      data = JSON.parse(this.response)
      localStorage.setItem("access_token", data.access_token)
    }
  }
  xhr.send()

}


//POST NEW TWEET
const formTweet = document.getElementById("form-tweet")
formTweet.addEventListener("submit", function (e) {
  e.preventDefault()
  let xhr = new XMLHttpRequest();
  let url = "http://127.0.0.1:5000/api/tweets";

  //get data from form
  let content = document.getElementById("tweets").value;
  //cek apakah terdapat file upload

  //validasi input
  if (content.trim().length < 0) return alert("Content tidak boleh kosong");

  let data = JSON.stringify({
    content: content
  });


  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json;charset=utf-8");
  xhr.setRequestHeader("Authorization", `Bearer ${localStorage.getItem('access_token')}`);
  xhr.onreadystatechange = function () {
    if (this.status == 200) {

      formTweet.reset()
      divEl.setAttribute("class", "alert alert-success");
      divEl.setAttribute("role", "alert");
      divEl.innerHTML = "Tweet berhasil ditambahkan !";
    } else {
      divEl.setAttribute("class", "alert alert-danger");
      divEl.setAttribute("role", "alert");
      divEl.innerHTML = JSON.parse(this.responseText);
    }
  };
  xhr.send(data);

  //give feedback
  const alertLoc = document.getElementById("tweet-alert")
  const divEl = document.createElement("div");
  alertLoc.appendChild(divEl);


})

//POST NEW TWEET MODAL
const modalFormTweet = document.getElementById("form-modal-tweet")
modalFormTweet.addEventListener("submit", function (e) {
  e.preventDefault()
  let xhr = new XMLHttpRequest();
  let url = "http://127.0.0.1:5000/api/tweets";

  //cek apakah terdapat file upload
  let formData = new FormData()
  let content_modal = document.getElementById("tweets-modal").value;
  let photo = document.getElementById("photo")
  if (content_modal.trim().length < 0) return alert("Content tidak boleh kosong");

  if (content_modal.trim().length > 0) {

    formData.append("content", content_modal)
    formData.append("file", photo.files[0])

    if (formData.get("content").trim().length < 0) return alert("Content tidak boleh kosong")
  }
//validasi input

xhr.open("POST", url, true);
xhr.setRequestHeader("Authorization", `Bearer ${localStorage.getItem('access_token')}`);
xhr.send(formData);
xhr.onreadystatechange = function () {
    if (this.status == 200) {
      formTweet.reset()
      divEl.setAttribute("class", "alert alert-success");
      divEl.setAttribute("role", "alert");
      divEl.innerHTML = "Tweet berhasil ditambahkan !";
    } else {
      divEl.setAttribute("class", "alert alert-danger");
      divEl.setAttribute("role", "alert");
      divEl.innerHTML = JSON.parse(this.responseText);
    }
  };

  //give feedback
  const alertLoc = document.getElementById("tweet-alert")
  const divEl = document.createElement("div");
  alertLoc.appendChild(divEl);
})

const logout = document.getElementById("logout")
logout.addEventListener("click", function (e) {
  e.preventDefault()
  let xhr = new XMLHttpRequest();
  let url = "http://127.0.0.1:5000/api/auth/logout";

  xhr.open("POST", url, true);
  xhr.setRequestHeader("Authorization", `Bearer ${localStorage.getItem('access_token')}`);
  xhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
      localStorage.removeItem("access_token")
      window.location.href = "http://127.0.0.1:5173/login";
    }
  };
  xhr.send();
})
```
Blok kode JavaScript yang diberikan terdiri dari beberapa fungsi yang mengelola permintaan dan tanggapan dari backend, serta berinteraksi dengan elemen-elemen HTML untuk menampilkan data dan memberikan respons terhadap interaksi pengguna. Berikut adalah penjelasan langkah-langkahnya:
Fungsi get_data() untuk Mengambil dan Menampilkan Tweet:
- Fungsi get_data() menggunakan XMLHttpRequest untuk memuat data tweet dari backend dengan permintaan GET ke URL tertentu ("http://127.0.0.1:5000/api/tweets").
- Setelah menerima respons (status 200), data tweet diurai dan setiap tweet ditampilkan dalam elemen-elemen HTML (dibuat secara dinamis) sesuai dengan informasi dari respons.
Pembaruan Otentikasi dengan Fungsi refresh_token() pada Interval Waktu Tertentu:
- Fungsi refresh_token() dijalankan setiap detik (dalam setInterval) untuk memperbarui token akses. Fungsi ini mengirimkan permintaan POST ke endpoint tertentu ("http://127.0.0.1:5000/api/auth/refresh") untuk mendapatkan token akses baru dan menyimpannya ke penyimpanan lokal (localStorage).
Penambahan Tweet Baru Melalui Formulir dan Modal:
- Ada dua event listeners yang memantau pengiriman tweet baru baik melalui formulir standar maupun melalui sebuah modal.
- Saat formulir disubmit, fungsi tersebut melakukan validasi data, mengirim permintaan POST ke backend, dan memberikan respons terkait berhasil atau tidaknya penambahan tweet.
Fungsi logout() untuk Logout Pengguna:
- Fungsi ini dipanggil saat pengguna mengklik tombol logout. Permintaan POST dikirimkan ke endpoint "http://127.0.0.1:5000/api/auth/logout" untuk logout pengguna, kemudian halaman diarahkan kembali ke halaman login.

### Code 15
```
const formLogin = document.getElementById("form-login")
formLogin.addEventListener("submit", function(e){
    e.preventDefault();
  
    let xhr = new XMLHttpRequest();
    let url = "/api/auth/login";
  
    //get data from form
    username = document.getElementById("username").value;
    password = document.getElementById("password").value;
  
    //validasi input
    if (username.trim().length < 0) return alert("Username tidak boleh kosong");
    if (password.trim().length < 0) return alert("password tidak boleh kosong");
  
    let data = JSON.stringify({
      username: username,
      password: password,
    });
  
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/json;charset=utf-8");
    
    xhr.onreadystatechange = function () {
      if (this.readyState == 4 && this.status == 200) {               
        //   formLogin.reset()
        let data = JSON.parse(this.response)
        //save to token to localStorage
        localStorage.setItem("access_token", data.access_token)
        window.location.href = "/";
      }
  };
    xhr.send(data);

    const alertLoc = document.getElementById("alert-loc")
    const div = document.createElement("div");
    alertLoc.append(div);
})
```
Blok kode JavaScript di atas merupakan fungsi yang mengelola proses autentikasi saat pengguna melakukan login. Penjelasannya dapat diuraikan sebagai berikut:
- Event Listener untuk Form Login:
formLogin adalah variabel yang menampung elemen HTML form untuk proses login. addEventListener memantau kejadian saat form tersebut di-submit.
Fungsi saat Form Login Disubmit:
- Ketika pengguna mengirimkan formulir login, fungsi yang terpasang pada formLogin dijalankan.
Fungsi tersebut mencegah perilaku bawaan form (dengan e.preventDefault()), sehingga halaman tidak melakukan reload saat formulir disubmit.
- Proses Login:
Sebuah objek XMLHttpRequest (xhr) dibuat untuk mengirimkan permintaan POST ke endpoint "/api/auth/login".
Data login diambil dari elemen formulir dengan getElementById.
Terdapat validasi sederhana untuk memastikan bahwa input username dan password tidak kosong. Jika kosong, maka akan muncul pesan peringatan melalui alert.
- Penanganan Respons dari Server:
Setelah mengirim permintaan, xhr.onreadystatechange mengelola respons dari server.
Jika respons dikembalikan dengan status 200 (sukses), informasi yang diterima diurai dari format JSON. Token akses (access_token) yang diperoleh dari respons server disimpan ke dalam penyimpanan lokal browser (localStorage).
Setelah penyimpanan token, pengguna diarahkan kembali ke halaman utama ("/") dengan menggunakan window.location.href.
- Pemberitahuan kepada Pengguna:
Terdapat elemen HTML untuk menampilkan pesan ke pengguna, diidentifikasi sebagai alert-loc. Ketika terjadi kesalahan dalam pengiriman formulir (misalnya, input kosong), pesan kesalahan akan ditampilkan di bagian tersebut sebagai elemen baru (<div>).

### Code 16
Code terdapat pada Flask/app/static/assets/js/script-register.js
```
const formRegister = document.getElementById("form-register");
formRegister.addEventListener("submit", function (e) {
  e.preventDefault();
  
  let xhr = new XMLHttpRequest();
  let url = "/api/auth/register";

  //get data from form
  username = document.getElementById("username").value;
  email = document.getElementById("email").value;
  password = document.getElementById("password").value;
  confirm_password = document.getElementById("confirm-password").value;
  role = document.getElementById("role").value
  //validasi input
  if (username == "") return alert("Username tidak boleh kosong");
  if (email == "") return alert("email tidak boleh kosong");
  if (password == "") return alert("password tidak boleh kosong");
  if (password != confirm_password)
    return alert("password yang dimasukan tidak sama");

  let data = JSON.stringify({
    username: username,
    email: email,
    password: password,
    role: role
  });
  

  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(data);
  xhr.onreadystatechange = function () {
    if (this.readyState == 4 && this.status == 200) {
        div.innerHTML = "Data berhasil ditambahkan !";
        div.setAttribute("class", "alert alert-success");
        div.setAttribute("role", "alert");
        formRegister.reset()
      }else{
        div.setAttribute("class", "alert alert-danger");
        div.innerHTML = "Ada masalah!";
        div.setAttribute("role", "alert");
    }
};

  //give feedback
  const alertLoc = document.getElementById("alert-loc")
  const div = document.createElement("div");
  alertLoc.append(div);
});
```
Blok kode JavaScript di atas bertanggung jawab dalam menangani proses pendaftaran pengguna baru melalui formulir pendaftaran pada aplikasi web. Berikut adalah penjelasan langkah-langkahnya:
- Pendefinisian Event Listener untuk Form Pendaftaran:
Variabel formRegister mengacu pada elemen HTML form yang digunakan untuk pendaftaran pengguna. addEventListener digunakan untuk memantau saat formulir tersebut disubmit.
- Fungsi saat Form Pendaftaran Disubmit:
Ketika pengguna mengirimkan formulir pendaftaran, fungsi yang terpasang pada formRegister dijalankan.
Fungsi tersebut mencegah perilaku bawaan form (dengan e.preventDefault()), sehingga halaman tidak melakukan reload saat formulir disubmit.
- Proses Pendaftaran:
Sebuah objek XMLHttpRequest (xhr) dibuat untuk mengirimkan permintaan POST ke endpoint "/api/auth/register".
Data pendaftaran diambil dari elemen formulir dengan menggunakan getElementById.
- Validasi Input:
Terdapat beberapa validasi yang dilakukan sebelum mengirimkan data pendaftaran. Hal ini mencakup pengecekan apakah field username, email, password, dan konfirmasi password telah diisi, serta apakah password sesuai dengan konfirmasi password.
- Pengiriman Data ke Server:
Setelah validasi input, data yang telah dikumpulkan dikirim ke server menggunakan metode POST.
Proses pengiriman data tersebut ditangani melalui XMLHttpRequest.
- Penanganan Respons dari Server:
Setelah pengiriman data, xhr.onreadystatechange mengelola respons dari server.
Jika respons dikembalikan dengan status 200 (sukses), maka pesan berhasil ditambahkan akan ditampilkan ke pengguna sebagai notifikasi bahwa pendaftaran telah berhasil.
Jika terjadi masalah dalam proses pendaftaran, pesan kesalahan akan ditampilkan sebagai notifikasi.
- Pemberitahuan kepada Pengguna:
Terdapat elemen HTML untuk menampilkan pesan kepada pengguna yang ditempatkan di bagian dengan id "alert-loc". Ketika terjadi kesalahan dalam pengiriman formulir (misalnya, input kosong atau kesalahan pada password), pesan kesalahan atau pesan sukses akan ditampilkan sebagai elemen baru (<div>).

### Code 17
Code terdapat pada vue_project/src/component/UI/button.vue
```
<template>
  <button :type="btnType" class="bg-green-500 p-2 rounded-md text-white hover:bg-green-800"
  @click="$emit('handleClick')">
    {{name}}
  </button>
</template>


<script setup>
defineProps({
    name: String,
    btnType: String,
})

defineEmits(['handleClick'])
</script>
```
Blok kode tersebut adalah komponen Vue yang menggunakan fitur script setup untuk memfasilitasi definisi properti dan event. Penjelasannya sebagai berikut:
Template:
- Terdapat sebuah tombol yang mengikuti properti yang diberikan dalam atribut btnType dan name. Tombol ini akan menampilkan teks yang didefinisikan oleh properti name.
- Atribut btnType digunakan untuk menentukan tipe dari tombol tersebut (contohnya: primary, secondary, dll.).
- Saat tombol tersebut diklik, sebuah event bernama handleClick akan dipancarkan (emit) untuk memberitahu komponen induk bahwa tombol telah ditekan.
Script Setup:
- Bagian script setup adalah bagian dari komposisi komponen Vue yang menggunakan fitur baru dalam Vue 3.
- defineProps digunakan untuk mendefinisikan properti yang diterima oleh komponen. Dalam hal ini, ada dua properti: name yang merupakan tipe string untuk menampilkan teks pada tombol, dan btnType yang juga merupakan tipe string dan menentukan tampilan tombol.
- defineEmits digunakan untuk mendefinisikan event yang akan dipancarkan (emit) oleh komponen ini. Dalam hal ini, komponen akan memancarkan event bernama handleClick ketika tombol diklik.
Dengan menggunakan setup script, komponen Vue dapat dengan mudah mendefinisikan properti yang diterima dan event yang dipancarkan, menjadikannya lebih mudah dipahami dan dikelola. Saat tombol ini digunakan dalam sebuah aplikasi Vue, properti-properti yang didefinisikan di atas akan memungkinkan pengguna untuk menyesuaikan teks dan tampilan tombol, serta memungkinkan interaksi dengan komponen lain melalui event yang dipancarkan.

### Code 18
Code terdapat pada vue_project/src/component/UI/card.vue
```
<template>
    <div class="bg-gray-200 mt-3 p-5 rounded-sm space-y-5">
        <p>{{ props.content }}</p>
        <div class="user">
            <span class="text-xs">{{ props.user }}</span>
        </div>
    </div>
</template>

<script setup>
const props = defineProps(['content', 'user'])

</script>
```
Blok kode tersebut merupakan sebuah komponen Vue yang menampilkan sebuah konten dan nama pengguna (user). Penjelasannya adalah sebagai berikut:
- Template:
Terdapat sebuah div dengan gaya visual tertentu, menampilkan konten yang diterima dari properti content.
Di dalam div tersebut, terdapat sebuah bagian yang menampilkan nama pengguna (user) dalam sebuah elemen span dengan gaya visual yang ditentukan.
- Script Setup:
Bagian script setup adalah bagian dari komposisi komponen Vue yang menggunakan fitur baru dalam Vue 3.
defineProps digunakan untuk mendefinisikan properti yang diterima oleh komponen. Dalam hal ini, ada dua properti: content yang berisi teks yang akan ditampilkan, dan user yang berisi nama pengguna yang akan ditampilkan.
Dengan menggunakan properti props yang didefinisikan, komponen ini dapat menerima data dari luar dan menampilkannya sesuai dengan tata letak yang telah ditentukan. Sebagai hasilnya, komponen ini bisa digunakan berulang kali di dalam aplikasi Vue untuk menampilkan konten dengan pengguna yang berbeda-beda tanpa harus menuliskan ulang kode yang sama.

### Code 19
Code terdapat pada vue_project/src/component/UI/customTextArea.vue
```
<template>
  <div class="flex flex-col">
    <label for="Tweet">{{label}}</label>
    <textarea
      rows="5"
      cols="20"
      class="border-b-4 border-green-300 focus:outline-none focus:border-b-4 focus:border-green-800"
      :value="modelValue" @input="$emit('update:modelValue', $event.target.value)"
    ></textarea>
  </div>
</template>

<script setup>
defineProps(['label', 'modelValue'])
defineEmits(['update:modelValue'])
</script>
```
Blok kode tersebut adalah sebuah komponen Vue yang memperlihatkan sebuah input area teks atau textarea, yang berfungsi untuk memasukkan teks. Penjelasan detailnya adalah sebagai berikut:
- Template:
Terdapat sebuah div dengan dua bagian. Pertama, terdapat sebuah label yang menunjukkan tujuan dari area teks tersebut sesuai dengan properti label.
Kedua, terdapat sebuah textarea yang memperlihatkan area input teks. Properti modelValue digunakan untuk menampilkan isi teks yang dimasukkan dan diatur menggunakan directive :value.
Ketika teks diubah (input), event $emit dengan nama update:modelValue dipancarkan, mengirimkan nilai yang diinputkan ke dalam komponen induk menggunakan $event.target.value.
- Script Setup:
Bagian script setup merupakan bagian komposisi komponen Vue yang menggunakan fitur baru dalam Vue 3.
defineProps digunakan untuk mendefinisikan properti yang diterima oleh komponen, dalam hal ini, label dan modelValue.
defineEmits digunakan untuk mendefinisikan event yang akan dipancarkan oleh komponen. Di sini, komponen akan memancarkan event update:modelValue yang mengirimkan nilai teks yang diinputkan kembali ke komponen induk.
Dengan cara ini, komponen textarea ini memungkinkan pengguna untuk memasukkan teks sesuai dengan label yang diberikan, sambil memperbarui data yang dimasukkan ke komponen induk melalui event yang dipancarkan. Kelebihannya, komponen ini dapat digunakan kembali dalam aplikasi untuk memasukkan teks dengan label yang berbeda-beda tanpa harus menulis ulang kode yang serupa.

### Code 20
Code terdapat pada vue_project/src/component/UI/form.vue
```
<template>
  <form @submit.prevent class="flex flex-col bg-gray-100 p-5 rounded-md w-100 space-y-3">
    <slot>
      <buttonC />
    </slot>
  </form>
</template>

<script setup>
import buttonC from "@/components/UI/button.vue";
</script>
```
Blok kode tersebut adalah sebuah komponen Vue yang menampilkan sebuah formulir dengan properti khusus yang memungkinkan pengguna untuk menambahkan konten di dalamnya. Penjelasan rinci dari kode tersebut adalah sebagai berikut:
- Template:
Terdapat sebuah form yang mendengarkan event submit (dengan menggunakan modifier .prevent agar tidak terjadi aksi refresh default pada submit) dan memiliki kelas CSS tertentu.
Di dalam form, terdapat sebuah tag slot yang memungkinkan pengguna memasukkan konten tambahan. Jika tidak ada konten yang dimasukkan, secara default akan ditampilkan komponen <buttonC />.
- Script Setup:
Bagian script setup adalah bagian komposisi komponen Vue dengan menggunakan fitur baru dari Vue 3.
Terdapat penggunaan import untuk memuat komponen buttonC dari alamat yang ditentukan (@/components/UI/button.vue), yang kemudian dimasukkan ke dalam komponen saat komponen tersebut di-render.
Dengan penggunaan slot, komponen formulir ini memberikan fleksibilitas kepada pengguna untuk menambahkan konten sesuai kebutuhan di dalam formulir tersebut. Ketika komponen formulir digunakan, pengguna dapat menyematkan elemen atau komponen apa pun ke dalamnya, dan jika tidak ada elemen yang disematkan, secara default akan muncul komponen <buttonC />.

### Code 21
Code terdapat pada vue_project/src/component/UI/input.vue
```
<template>
    <label :for="idInput">{{ labelName }}</label>
    <input :type="inputType" :value="modelValue" @input="$emit('update:modelValue', $event.target.value)"
        class="rounded-mg bg-gray-300 focus:bg-white focus:outline-none focus:border-b-4 focus:border-green-500 h-10">
</template>

<script setup>
defineProps(['idInput', 'labelName', 'inputType', 'modelValue'])
defineEmits(['update:modelValue'])
</script>
```
Blok kode di atas adalah sebuah komponen Vue yang dirancang untuk menampilkan label dan input pada suatu formulir. Penjelasannya sebagai berikut:
- Template:
Terdapat sebuah label yang menggunakan properti for dan diatur nilainya sesuai dengan properti idInput.
Bagian input memiliki properti seperti type, value, dan event listener @input. Properti type diatur oleh properti inputType yang memungkinkan penentuan jenis input (seperti 'text', 'password', dll.). Nilai yang diinputkan akan diatur sesuai dengan properti modelValue.
Penggunaan event @input akan memancarkan event update:modelValue dengan nilai yang diisi pada input. Ini memungkinkan pembaruan data di tingkat induk (parent) saat nilai input diubah.
- Script Setup:
Bagian script setup adalah bagian komposisi komponen Vue dengan menggunakan fitur baru dari Vue 3.
Menggunakan defineProps untuk mendeklarasikan properti yang digunakan dalam komponen.
Menggunakan defineEmits untuk mendeklarasikan event yang dipancarkan oleh komponen.
Komponen ini memungkinkan fleksibilitas dalam menampilkan label dan input dengan jenis yang bervariasi serta memungkinkan pembaruan data secara langsung ke komponen induk ketika nilai input diubah.

### Code 22
Code terdapat pada vue_project/src/component/UI/modals.vue
```
<template>
  <Dialog :open="isOpen" @close="toggleModal">
    <div class="fixed inset-0 bg-black/30" aria-hidden="true" />
    <div class="fixed inset-0 flex w-100 items-center justify-center p-4">
    <DialogPanel class="bg-white p-5 rounded-md">
      <DialogTitle class="text-2xl my-6">Form Upload</DialogTitle>
      <DialogDescription>
        <formC class="flex gap-5 flex-col">
            <div class="flex flex-col">
                <label for="uploadFile">Upload File</label>
                <input type="file" id="uploadFile" class="input:border-none">
            </div>
            <div class="flex flex-col">
                <textAreaC label="Tweet"></textAreaC>
            </div>
        </formC>
      </DialogDescription>
      <div class="flex gap-5 mt-4">
          <buttonC @handle-click="$emit('closeModal')" name="Close"/>
          <buttonC @handle-click="$emit('uploadButton')" name="Upload"/>
      </div>

    </DialogPanel>
    </div>
  </Dialog>
</template>

<script setup>
import { ref } from "vue";
import {
  Dialog,
  DialogPanel,
  DialogTitle,
  DialogDescription,
} from "@headlessui/vue";

import buttonC from "./button.vue";
import formC from "./form.vue";
import textAreaC from "./customTextArea.vue";

defineProps(['isOpen']);

defineEmits(['closeModal'])

</script>
```
Kode tersebut merupakan sebuah komponen Vue yang dirancang untuk menampilkan dialog/modal form untuk mengunggah file. Berikut penjelasan dalam paragraf:
Template:
- Komponen menggunakan Dialog dari Headless UI Vue untuk memunculkan dialog modal dengan properti :open yang mengontrol visibilitasnya melalui properti isOpen.
- Terdapat tombol "Close" dan "Upload" yang digerakkan oleh komponen buttonC dengan event @handle-click yang akan memancarkan event saat tombol tersebut ditekan.
- Dalam bagian dialog, terdapat elemen form dengan label "Upload File" yang memiliki elemen input type="file" untuk mengunggah file dan komponen textAreaC yang merupakan custom component textarea.
Script Setup:
- Menggunakan ref dari Vue untuk menangani status dialog/modal, diwakili oleh properti isOpen.
- Menggunakan komponen-komponen dari Headless UI Vue untuk membangun struktur dialog modal, seperti Dialog, DialogPanel, DialogTitle, dan DialogDescription.
- Mengimpor dan menggunakan komponen-komponen kustom seperti buttonC, formC, dan textAreaC.
- Melalui defineProps, komponen menerima properti isOpen yang mengontrol visibilitas dialog.
- Dengan defineEmits, komponen ini memancarkan event closeModal saat tombol "Close" ditekan, dan uploadButton saat tombol "Upload" ditekan. Event ini dapat digunakan di tingkat induk (parent) yang menggunakan komponen ini untuk menangani perubahan status dialog modal.
Komponen ini memfasilitasi tampilan dialog/modal form untuk mengunggah file dengan tombol untuk menutup dan mengunggah file serta kolom input untuk teks.

### Code 23
```
<template>
    <nav class="flex justify-around items-center bg-green-500 p-3 text-white">
        <h1>Simple Twitter</h1>
        <ul class="flex gap-5">
            <RouterLink to="/" exact active-class="border-2 border-white p-1">Home</RouterLink>
            <RouterLink to="/leaderboard" exact active-class="border-2 border-white p-1">Leaderboard</RouterLink>
            <RouterLink to="/login" exact active-class="border-2 border-white p-1">Login</RouterLink>
            <RouterLink to="/register" exact active-class="border-2 border-white p-1">Register</RouterLink>
            <a to="/logout" class="border-2 border-white p-1" @click="handleLogout">Logout</a>
            <!-- <a :href="urlAdmin" class="border-2 border-white p-1">Admin</a> -->
        </ul>
    </nav>
</template>

<script setup>
import {RouterLink} from 'vue-router'
import Swal from 'sweetalert2'
import { useRouter } from 'vue-router';
import { useAuthStore } from '../../stores/authStore';


const urlAdmin = import.meta.env.VITE_API_BASEURL + "/admin"
const {removeToken} = useAuthStore()
const router = useRouter()
const handleLogout = () => {
    Swal.fire({
  title: 'Are you sure?',
  text: "You won't be able to revert this!",
  icon: 'warning',
  showCancelButton: true,
  confirmButtonColor: '#3085d6',
  cancelButtonColor: '#d33',
  confirmButtonText: 'Yes, delete it!'
}).then((result) => {
  if (result.isConfirmed) {
    removeToken()
    router.push('/login')
  }
})
}
</script>
```
Kode ini merupakan bagian dari komponen navigasi yang berisi tautan menu navigasi di sebuah aplikasi "Simple Twitter". Berikut penjelasan terkait kode tersebut:
Template:
- <nav>: Menampilkan bagian navigasi, menggunakan elemen <nav> untuk menyusun elemen-elemen navigasi.
- "Simple Twitter": Menampilkan judul atau nama aplikasi di bagian kiri atas.
- Daftar tautan navigasi menggunakan komponen <RouterLink> untuk berpindah antar halaman aplikasi. Tautan ini akan menyesuaikan properti active-class ketika tautan tersebut aktif.
- Ada juga tautan "Logout" yang akan memicu fungsi handleLogout ketika diklik.
Script Setup:
- Menggunakan RouterLink dari vue-router untuk membuat tautan yang terhubung ke rute aplikasi.
- Menggunakan Swal dari sweetalert2 untuk menampilkan popup konfirmasi saat melakukan logout.
- useAuthStore digunakan dari store authStore yang memungkinkan untuk mengakses dan mengelola informasi autentikasi pengguna.
- Didefinisikan variabel urlAdmin yang diinisialisasi dengan nilai dari environment variable untuk mengarahkan ke halaman admin.
- Dideklarasikan fungsi handleLogout yang akan memunculkan konfirmasi menggunakan SweetAlert saat pengguna akan logout, dan jika dikonfirmasi, akan menghapus token autentikasi dan mengarahkan pengguna kembali ke halaman login menggunakan router.push('/login').
Komponen ini menyediakan tautan navigasi antar halaman dengan kemampuan logout yang mengonfirmasi aksi pengguna sebelum benar-benar melakukan logout.

### Code 24
Code terdapat pada vue_project/src/composable/useAuth.js
```
import axios from 'axios'
import {ref} from 'vue'

export function useAuth(){

    const errorMsg = ref(null)
    const tryAuth = async (url, formData) => {
        try{
            axios.defaults.withCredentials = true
            const response = await axios.post(url, formData)
            return response
        }catch(e){
            errorMsg.value = e.response.data.error
        }
    }

    return {
        tryAuth,
        errorMsg
    }
}
```
Kode di atas adalah bagian dari sebuah fungsi Vue 3 yang disebut useAuth. Fungsi ini dirancang untuk mengelola autentikasi dalam aplikasi. Berikut adalah penjelasan komponen-komponennya:
- axios adalah pustaka JavaScript yang digunakan untuk melakukan permintaan HTTP. Fungsi ini mengimpor axios untuk berkomunikasi dengan backend server.
- ref adalah salah satu fitur Vue 3 yang digunakan untuk membuat variabel reaktif. Dalam konteks ini, kita menggunakan ref untuk membuat variabel errorMsg yang akan digunakan untuk menyimpan pesan kesalahan autentikasi.
- useAuth adalah fungsi utama yang digunakan untuk mengelola autentikasi.
- errorMsg adalah variabel reaktif yang akan menyimpan pesan kesalahan autentikasi. Awalnya, nilainya diatur sebagai null.
- tryAuth adalah fungsi yang mengirimkan permintaan autentikasi ke server. Fungsi ini menerima dua parameter:
- url: URL yang akan menjadi tujuan permintaan autentikasi.
- formData: Data formulir atau informasi yang akan dikirimkan dalam permintaan autentikasi.
- Dalam tryAuth, kita mencoba mengirim permintaan POST ke url dengan menggunakan axios. Permintaan ini umumnya digunakan untuk proses login atau registrasi.
- Jika permintaan berhasil (status 200 OK), maka responsenya akan dikembalikan.
- Jika terjadi kesalahan (status responsenya tidak 200), maka errorMsg akan diisi dengan pesan kesalahan yang diterima dari respons.
- Terakhir, fungsi tryAuth mengembalikan respons atau pesan kesalahan sesuai dengan hasil permintaan autentikasi.

### Code 25
Code terdapat pada vue_project/src/composable/useAxios.js
```
import axios from 'axios'
import {ref} from 'vue'
import axiosinstance from '../lib/axios/axiosInstance'

export function useAxios(){
    const tryFetch = async (url, page, per_page) => {
        try{
            const response = await axiosinstance.get(url, {
                params: {
                    page: page,
                    per_page: per_page
                }
            })
            return response
        }catch(e){
            console.log(e)
        }
    }

    const tryPost = async (url) => {
        try{
            const response = await axiosinstance.post(url, formData, {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
              }
            })
            return response
        }catch(e){
            console.log(e)
        }
    }

    const tryUpload = async (url) => {
        try{
            const response = await axiosinstance.post(url, formData, {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'multipart/form-data'
              }
            })
            return response
        }catch(e){
            console.log(e)
        }
    }

    return {
        tryFetch,
    }
}
```
Kode di atas adalah bagian dari sebuah fungsi Vue 3 yang disebut useAxios. Fungsi ini bertujuan untuk menggunakan Axios dalam koneksi ke backend server. Berikut adalah penjelasan rinci dari komponen-komponen dalam fungsi useAxios:
- axios adalah pustaka JavaScript yang digunakan untuk melakukan permintaan HTTP. axios diimpor untuk digunakan dalam fungsi ini.
- ref adalah fitur Vue 3 yang digunakan untuk membuat variabel reaktif.
- axiosinstance adalah instance dari Axios yang telah dikonfigurasi sebelumnya. Axios instance ini mungkin telah diatur dengan berbagai konfigurasi seperti base URL, interceptor, atau konfigurasi lainnya.
- useAxios adalah fungsi utama yang bertujuan untuk mengelola permintaan HTTP menggunakan Axios.
- tryFetch adalah fungsi yang mengirimkan permintaan GET ke server dengan URL tertentu beserta query page dan per_page. Fungsi ini menerima tiga parameter:
url: URL tujuan permintaan.
page: Nomor halaman.
per_page: Jumlah data per halaman.
- Dalam tryFetch, permintaan GET dilakukan menggunakan Axios instance (axiosinstance) yang telah dikonfigurasi sebelumnya. Data query page dan per_page disertakan dalam permintaan menggunakan objek params.
- Jika permintaan berhasil, fungsi ini akan mengembalikan respons.
- tryPost dan tryUpload mirip dengan tryFetch tetapi mengirimkan permintaan POST ke server dengan menggunakan metode axiosinstance.post. tryPost digunakan untuk permintaan dengan tipe konten 'application/json', sedangkan tryUpload untuk tipe konten 'multipart/form-data'.
- Dalam tryPost dan tryUpload, permintaan POST dilakukan menggunakan Axios instance dengan menyertakan accessToken dan formData yang diperlukan, serta jenis konten yang sesuai.
- Jika terjadi kesalahan dalam permintaan (catch block), fungsi akan menangkap kesalahan dan menuliskannya pada konsol.
- Fungsi useAxios mengembalikan tryFetch dan bisa juga mengembalikan tryPost dan tryUpload tergantung pada kebutuhan dalam aplikasi yang sedang dikembangkan.

### Code 26
Code terdapat ini vue_project/src/lib/axios/axiosInstance.js
```
import axios from 'axios'
import { useAuthStore } from '../../stores/authStore';
import { storeToRefs } from 'pinia';

// const store 
const axiosinstance = axios.create({
    baseURL: import.meta.env.VITE_API_BASEURL,
    timeout: 100000,
  });
  axiosinstance.interceptors.request.use(
    (config) => {
        const accessToken = localStorage.getItem("accessToken")
        if(accessToken){
            config.headers.Authorization = `Bearer ${accessToken}`
        }
        return config
    },
    (error) => {
        return Promise.reject(error)
    }
  )

axiosinstance.interceptors.response.use(
    (response) => {
        return response
    },
    async (error) => {
        const originalRequest = error.config
        if(error.response.status == 401 && !originalRequest._retry){
            originalRequest._retry = true
            try{
                const refreshToken = localStorage.getItem('refreshToken')
                const response = await axios.post(import.meta.env.VITE_API_BASEURL + '/api/auth/refresh', null, {
                    headers: {
                        Authorization: `Bearer ${refreshToken}`
                    }
                })
                const newAccessToken = response.data.access_token
                localStorage.setItem('accessToken', newAccessToken)
                originalRequest.headers.Authorization = `Bearer ${newAccessToken}`
                return axiosinstance(originalRequest)
            }catch(err){
                console.log(err)
            }
        }
    }
)

  export default axiosinstance
```
Kode di atas menggunakan Axios untuk membuat instance yang digunakan untuk melakukan permintaan ke backend server. Berikut penjelasan rinci tentang apa yang dilakukan dalam kode tersebut:
- import menyertakan pustaka Axios yang memungkinkan untuk melakukan permintaan HTTP.
- useAuthStore adalah fungsi yang diimpor dari authStore untuk mengakses data autentikasi pada store.
- storeToRefs adalah fungsi dari pinia yang digunakan untuk mengonversi store ke ref agar kompatibel dengan Vue 3.
- axios.create digunakan untuk membuat instance Axios yang akan digunakan untuk semua permintaan. Di sini, instance dibuat dengan konfigurasi tertentu seperti base URL dari backend (VITE_API_BASEURL) dan timeout sebesar 100000 milliseconds.
- axiosinstance.interceptors.request.use menambahkan interceptor ke permintaan sebelum dilakukan. Interceptor ini bertujuan untuk menyisipkan header Authorization yang berisi token akses (accessToken) ke dalam setiap permintaan. Jika token akses tersedia di local storage, ia akan ditambahkan sebagai header Authorization.
- axiosinstance.interceptors.response.use menambahkan interceptor ke respons sebelum dikembalikan ke pemanggil permintaan aslinya. Interceptor ini menangani respons dari server dan menangani kasus di mana token akses (accessToken) kadaluarsa (status 401).
Interceptors pada Axios instance memungkinkan untuk menangani permintaan dan respons sebelum dan setelah dilakukan, sehingga digunakan di sini untuk mengelola otentikasi, memasukkan header, dan menangani situasi di mana token akses kadaluarsa.

### Code 27
Code terdapat pada vue_project/src/router/index.js
```
import { createRouter, createWebHistory} from 'vue-router'

import homeC from "../view/home.vue"
import leaderboardC from "../view/leaderboard.vue"
import loginC from "../view/login.vue"
import registerC from "../view/register.vue"
import { useAuthStore } from '../stores/authStore.js'

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
        {
            path: "/",
            name: "home",
            component: homeC,
            meta: {
                requiresAuth : true
            }
        },
        {
            path: "/leaderboard",
            name: "leaderboard",
            component: leaderboardC,
            meta: {
                requiresAuth : true
            }
        },
        {
            path: "/login",
            name: "login",
            component: loginC
        },
        {
            path: "/register",
            name: "register",
            component: registerC
        },
    ]
})

router.beforeEach((to, from, next) => {
    const {isAuthenticated} = useAuthStore()

    if(to.meta.requiresAuth){
        if(isAuthenticated){
            next()
        }else{
            next('/login')
        }
    }else{
        next()
    }
})
export default router
```
Kode di atas menggunakan Vue Router untuk mengelola rute dalam aplikasi web. Berikut adalah penjelasan rinci tentang apa yang dilakukan dalam kode tersebut:
- import mengambil beberapa fungsi dan modul dari vue-router yang digunakan untuk membuat router.
- Kode membuat instance router menggunakan createRouter yang mengatur pengaturan history menggunakan createWebHistory, serta menentukan rute dan komponen yang terkait.
- routes adalah daftar rute yang didefinisikan untuk aplikasi, yang terdiri dari beberapa rute seperti halaman utama (homeC), leaderboard (leaderboardC), login (loginC), dan register (registerC).
- Setiap rute memiliki properti meta yang menandai apakah akses ke rute tersebut memerlukan otentikasi (requiresAuth: true). Misalnya, rute untuk halaman utama dan leaderboard memerlukan otentikasi, sedangkan rute untuk login dan register tidak memerlukannya.
- router.beforeEach adalah metode untuk mengatur navigasi sebelum perubahan rute. Di sini, ia memeriksa jika rute yang dituju membutuhkan otentikasi (requiresAuth). Jika iya, ia memeriksa status otentikasi menggunakan fungsi dari useAuthStore yang disimpan dalam variabel isAuthenticated dari store.
- Jika pengguna terotentikasi (isAuthenticated bernilai true), maka navigasi ke rute selanjutnya dilanjutkan dengan memanggil next(). Namun, jika tidak terotentikasi, pengguna akan diarahkan kembali ke halaman login (/login) menggunakan next('/login').
- Jika rute tidak memerlukan otentikasi (requiresAuth: false), navigasi akan diteruskan ke rute berikutnya menggunakan next().

### Code 28
```
import {defineStore} from 'pinia'
import {ref, computed, watch} from 'vue'

export const useAuthStore = defineStore('auth', () => {
    const accessToken = ref(null)
    const refreshToken = ref(null)

    const persistAccessToken = localStorage.getItem("accessToken")
    const persistRefreshToken = localStorage.getItem("refreshToken")

    if((persistAccessToken != persistRefreshToken) != null){
        accessToken.value = persistAccessToken
        refreshToken.value = persistRefreshToken
    }

watch(accessToken.value, (newAccessToken) => {
    accessToken = newAccessToken
})


    const isAuthenticated = computed(() => {
        return accessToken.value != null
    })

    //actions
    const setToken = (access_token, refresh_token) => {
        localStorage.setItem('accessToken', access_token)
        localStorage.setItem('refreshToken', refresh_token)
        accessToken.value = access_token
        refreshToken.value = refresh_token
    }
    const removeToken = () => {
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
        accessToken.value = null
        refreshToken.value = null
    }

    return{
        accessToken, refreshToken, isAuthenticated, setToken, removeToken
    }
},
)
```
Kode di atas merupakan bagian dari definisi sebuah store bernama useAuthStore yang dibuat dengan Pinia, sebuah state management untuk Vue.js. Berikut adalah penjelasan mengenai kode tersebut:
- defineStore digunakan untuk membuat store auth yang mengelola data otentikasi (accessToken, refreshToken) dan logika terkait otentikasi pengguna.
- accessToken dan refreshToken adalah variabel ref (reactive reference) yang menampung token otentikasi dan token penyegaran yang awalnya diberi nilai null.
- persistAccessToken dan persistRefreshToken adalah variabel yang diinisialisasi dengan nilai dari localStorage, yang bertujuan untuk mempertahankan informasi otentikasi pengguna antara sesi aplikasi.
- watch adalah fungsi yang memantau perubahan pada accessToken. Namun, pada implementasinya, terdapat kesalahan dalam penugasan accessToken pada watch yang seharusnya menggunakan accessToken.value daripada mengganti kembali accessToken dengan nilai yang baru.
- isAuthenticated adalah variabel yang dihitung (computed) untuk menentukan apakah pengguna terotentikasi berdasarkan nilai dari accessToken. Jika accessToken memiliki nilai (tidak null), isAuthenticated akan mengembalikan true, menunjukkan bahwa pengguna sudah terotentikasi.
- setToken berfungsi untuk menetapkan token otentikasi dan penyegaran, serta menyimpannya di localStorage untuk mempertahankan sesi pengguna.
- removeToken digunakan untuk menghapus token otentikasi dan penyegaran dari localStorage dan menyertakan nilai null ke dalam accessToken dan refreshToken, menandakan pengguna tidak lagi terotentikasi.
- Objek yang dikembalikan dari useAuthStore berisi variabel accessToken, refreshToken, isAuthenticated, serta fungsi setToken dan removeToken. Variabel ini dapat diakses dan dimanfaatkan di seluruh aplikasi untuk memantau dan mengelola status otentikasi pengguna.

### Code 29
Code terdapat pada vue_project/src/view/home.vue
```
<template>
  <div class="mx-40">
    <h1 class="text-2xl mt-4 mb-4">Halaman Home</h1>
    <formC class="bg-gray-300 rounded p-6">
        <div class="flex flex-col">
          <label for="Tweet">{{label}}</label>
          <textareaC label="Tweet" v-model="tweet" />
          {{ tweet }}
        <div class="flex gap-5 mt-7">
            <buttonC name="Submit" @handle-click="postContent"/>
            <buttonC name="Upload File" @handle-click="toggleModal"/>
        </div>
        </div>
    </formC>
    
    <card v-for="item in data" :key="item.id" :content="item.content"
    :user="item.user"/>

    <!-- modal baru -->
    <div v-if="showModal" class="w-full">
        <modalVue :isOpen="showModal" @close-modal="toggleModal"/>
    </div>
    <div>
      <buttonC @click="prevItem" :disabled="page == 1" name="Previous" class="mx-2">Prev</buttonC>
      <buttonC @click="nextItem" :disabled="page == total_page" name="Next" class="mx-2">Next</buttonC>
    </div>
</div>
</template>

<script setup>
import navbar from "@/components/UI/navbar.vue";
import formC from "@/components/UI/form.vue";
import card from "@/components/UI/card.vue";
import buttonC from "@/components/UI/button.vue";
import textareaC from "@/components/UI/customTextArea.vue";
import modalVue from "../components/UI/modals.vue";
import { ref, onMounted, watch } from "vue";
import { useAxios } from "../composable/useAxios";
import axios from 'axios'
import { useAuthStore } from "../stores/authStore";
import{ storeToRefs } from "pinia";

const page = ref(1)
const per_page = ref(2)
const total_page = ref()
const total_item = ref()

const prevItem = () => {
  page.value--
}

const nextItem = () => {
  page.value++
}

watch(page, (newPage) => {
  handleFetching(newPage, per_page.value)
})

const stores = useAuthStore()
const { accessToken, refreshToken, isAuthenticated } = storeToRefs(stores)

const data = ref([])

const {tryFetch} = useAxios()
const tweet = ref('');

const handleFetching = async (page, per_page) => {
  const result = await tryFetch('/api/tweets', page, per_page)
  console.log(result)
  data.value = result.data.data
  console.log(data.value)
  total_page.value = result.data.total_page
  total_item.value = result.data.total_item
}

const toggleClick = () => {
    console.log("print")
}

const postContent = async () => {
  const result = await tryPost(import.meta.env.VITE_API_BASEURL + '/api/tweets', accessToken.value)
}

const toggleModal = () => {
  console.log("click");
  showModal.value = !showModal.value;
};

onMounted(() => {
  handleFetching()
})

</script>
```
Kode yang diberikan adalah bagian dari halaman Vue yang disusun dengan komponen-komponen tertentu dan logika aplikasi. Inilah penjelasan singkatnya:
- Template: Ini adalah bagian tampilan HTML halaman yang mencakup elemen-elemen seperti judul, formulir, kartu-kartu yang mewakili posting pengguna, dan modal. Terdapat juga tombol untuk mengirim posting dan navigasi halaman.
- Setup Script: Ini adalah bagian yang menggunakan Composition API untuk menginisialisasi variabel-variabel, mengakses komponen store yang digunakan untuk otentikasi, dan mendefinisikan fungsi-fungsi.
- Penggunaan Store: Kode ini menggunakan Pinia store untuk menyimpan data token otentikasi, yaitu accessToken dan refreshToken. Ini memungkinkan pengguna untuk masuk dan keluar dari aplikasi.
- handleFetching: Fungsi ini digunakan untuk memuat data posting dari server dan menampilkannya di halaman. Ini juga memungkinkan navigasi antara halaman dengan tombol "Prev" dan "Next".
- postContent: Fungsi ini bertanggung jawab atas pengiriman posting pengguna ke server.
- toggleModal: Fungsi ini mengontrol tampilan modal saat tombol "Upload File" ditekan.
- onMounted: Fungsi ini digunakan untuk memanggil handleFetching saat halaman dimuat.
Kode tersebut memungkinkan pengguna untuk membuat dan menampilkan posting, serta menavigasi antara halaman dengan tombol "Prev" dan "Next." Ia juga memiliki otentikasi pengguna yang digerakkan oleh store, yang memungkinkan pengguna masuk dan keluar dari aplikasi. Untuk keberhasilan penuh, beberapa perubahan dan penambahan mungkin diperlukan, terutama untuk mengimplementasikan logika yang hilang seperti tryPost dan showModal.

### Code 30
Code terdapat pada vue_project/src/view/leaderboard.vue
```
<template>
  <h1>Leaderboard</h1>
  <div class="flex w-full items-center">
    <div class="mx-auto w-1/2">
      <DataTable class="display" :columns="columns" :data="data.data" :options="options"/>
    </div>
  </div>
</template>

<script setup>
import DataTable from "datatables.net-vue3";
import DataTablesCore from "datatables.net-dt";
import { useAxios } from "../composable/useAxios";
import { ref, onMounted } from "vue";

DataTable.use(DataTablesCore);
const data = ref([]);
const { tryFetch } = useAxios();

const columns = [
  { data: "username", title: "username" },
  { data: "count_tweet", title: "Tweet Count" },
];

const options = {
    paging: false,
    searching: false,
    details: false,
    info: false,
}

const handleFetch = async () => {
  const res = await tryFetch("/api/counts");
  data.value = res.data;
  console.log(data.value);
};

onMounted(() => {
  handleFetch();
});
</script>

<style>
@import "datatables.net-dt";
</style>
```
Kode yang disediakan adalah bagian dari sebuah komponen Vue yang menampilkan data dalam bentuk leaderboard menggunakan library DataTables. Ini adalah penjelasan singkatnya:
- Template: Template berisi elemen-elemen HTML yang mencakup judul "Leaderboard" dan sebuah komponen DataTable yang menampilkan data dalam bentuk tabel. Tabel ini menggunakan properti dari columns, data, dan options untuk menampilkan informasi seperti username dan jumlah tweet.
- Setup Script: Bagian ini menggunakan Composition API untuk menginisialisasi variabel-variabel seperti data, columns, dan options. Komponen DataTable diperkenalkan dari pustaka datatables.net-vue3, sedangkan fungsi useAxios digunakan untuk mengambil data dari API.
- Penggunaan DataTables: DataTables adalah library yang digunakan untuk menyajikan data dalam format tabel yang interaktif. Dalam kode ini, DataTable diinisialisasi dengan columns untuk menentukan data yang akan ditampilkan, dan options untuk mengatur perilaku tabel seperti pembatasan paging, searching, info, dan sebagainya.
- Fetch Data: Fungsi handleFetch digunakan untuk mengambil data dari API yang ditentukan. Saat komponen dimuat (onMounted), fungsi handleFetch dipanggil untuk memuat data awal.
Komponen ini bertanggung jawab atas tampilan data leaderboard dalam format tabel yang interaktif, yang memungkinkan pengguna untuk melihat data pengguna berdasarkan jumlah tweet yang mereka miliki. Pada akhirnya, komponen ini memanfaatkan kekuatan dan fungsionalitas DataTables untuk menampilkan data dengan gaya yang teratur dan mudah dimengerti.

### Code 31
Code terdapat pada vue_project/src/view/login.vue
```
<template>
  <div class="p-20">
    <formC>
      <!-- <span v-if="errorMsg" class="bg-red-500 p-4"> {{ errorMsg }}</span> -->
      <inputC
        id-input="username"
        input-type="text"
        label-name="Username"
        v-model="userData.username"
      />
      <p v-if="validationError.username" class="text-red-500">
        {{ validationError.username }}
      </p>
      <inputC
        id-input="password"
        input-type="password"
        label-name="Password"
        v-model="userData.password"
      />
      <p v-if="validationError.password" class="text-red-500">
        {{ validationError.password }}
      </p>

      <buttonC name="Submit" btn-type="submit" @handle-click="handleLogin" />
      <RouterLink to="/register" class="text-blue-500 hover:underline"
        >Register</RouterLink
      >
    </formC>
  </div>
</template>

<script setup>
import formC from "../components/UI/form.vue";
import inputC from "../components/UI/input.vue";
import buttonC from "../components/UI/button.vue";
import { reactive, ref } from "vue";
import { useRouter, RouterLink } from "vue-router";
import { useAuth } from "../composable/useAuth";
import { useAuthStore } from "../stores/authStore";
import Swal from "sweetalert2";

const { setToken } = useAuthStore();

const success = ref(false);
const accessToken = ref();
const refreshToken = ref();

const { tryAuth, errorMsg } = useAuth();

const router = useRouter();

const userData = reactive({
  username: "",
  password: "",
});

const validationError = reactive({
  username: "",
  password: "",
});

const handleLogin = async () => {
  Object.keys(validationError).forEach((key) => {
    validationError[key] = "";
  });

  let isValid = ref(true);
  if (!userData.username) {
    validationError.username = "Username is required";
    isValid.value = false;
  }
  if (!userData.password) {
    validationError.password = "Password is required";
    isValid.value = false;
  }

  if (isValid) {
    const result = await tryAuth(
      import.meta.env.VITE_API_BASEURL + "/api/auth/login",
      userData
    );
    success.value = result.data.success;
    accessToken.value = result.data.access_token;
    refreshToken.value = result.data.refresh_token;
    setToken(accessToken.value, refreshToken.value);
    if (result.data.access == true) {
      Swal.fire("Welcome to Simple Twitter!");
      router.push("/");
    }
  }
};
</script>
```
Kode yang diberikan menggambarkan suatu formulir login dalam aplikasi yang menggunakan Vue. Berikut adalah penjelasan singkat dari kode tersebut:
- Template: Template berisi formulir login yang terdiri dari input untuk username, password, tombol untuk submit, dan sebuah tautan untuk menuju halaman registrasi jika pengguna belum memiliki akun. Setiap input memiliki pesan kesalahan validasi yang ditampilkan jika input tidak diisi.
- Setup Script: Bagian ini menggunakan Composition API Vue. Variabel yang dideklarasikan adalah userData yang menyimpan nilai username dan password dari formulir, dan validationError yang digunakan untuk menampilkan pesan kesalahan validasi. Fungsi handleLogin digunakan untuk mengelola logika autentikasi saat tombol submit ditekan.
- Logika Autentikasi: Saat tombol submit ditekan, terjadi validasi untuk memeriksa apakah input username dan password telah diisi. Jika tidak, pesan kesalahan ditampilkan di bawah masing-masing input. Jika kedua input telah diisi, permintaan otentikasi dikirim ke server menggunakan fungsi tryAuth. Jika autentikasi berhasil (berhasil mendapatkan akses), pesan selamat datang muncul dan pengguna diarahkan ke halaman utama.
Kode ini secara keseluruhan bertanggung jawab untuk memvalidasi input, mengelola permintaan otentikasi ke server, dan memberikan umpan balik kepada pengguna terkait status otentikasi mereka. Ini memastikan bahwa input yang dibutuhkan telah diisi sebelum permintaan otentikasi dikirim, menggabungkan otentikasi dengan penggunaan SweetAlert untuk memberikan pengalaman yang lebih interaktif.

### Code 32
Code terdapat pada vue_project/src/view/register.vue
```
<template>
  <div class="p-20">
    <formC>
      <p v-if="success" class="bg-green-500 p-3 text-white">{{ message }}</p>
      <inputC
        id-input="username"
        input-type="text"
        label-name="Username"
        v-model="userData.username"
      />
      <inputC
        id-input="email"
        input-type="email"
        label-name="Email"
        v-model="userData.email"
      />
      <inputC
        id-input="password"
        input-type="password"
        label-name="Password"
        v-model="userData.password"
      />
      <inputC
        id-input="confirm_password"
        input-type="password"
        label-name="Confirm Password"
        v-model="confirmPassword"
      />
      <buttonC name="Submit" btn-type="submit" @handle-click="handleRegister" />
      <RouterLink to="/login" class="text-blue-500 hover:underline"
        >Kembali ke login</RouterLink>
    </formC>
  </div>
</template>

<script setup>
import formC from "../components/UI/form.vue";
import inputC from "../components/UI/input.vue";
import buttonC from "../components/UI/button.vue";
import { reactive, ref } from "vue";
import { useAuth } from "../composable/useAuth";
import { RouterLink } from "vue-router";

const userData = reactive({
  username: "",
  password: "",
  email: "",
});

const confirmPassword = ref("");

const success = ref(false);
const message = ref();

const { tryAuth } = useAuth();

const handleRegister = async () => {
  if (confirmPassword.value == userData.password) {
    const result = await tryAuth(
      import.meta.env.VITE_API_BASEURL + "/api/auth/register",
    userData
    );
    success.value = result.data.success;
    message.value = result.data.message;
  }
};
</script>
```
Kode yang diberikan menunjukkan formulir pendaftaran (register form) dalam aplikasi yang menggunakan Vue. Berikut penjelasan singkatnya:
- Template: Template berisi formulir pendaftaran yang meminta pengguna untuk memasukkan username, email, password, dan mengonfirmasi password. Jika pendaftaran berhasil, pesan kesuksesan akan ditampilkan di atas formulir, sedangkan jika terdapat perbedaan antara password dan konfirmasi password, tidak akan dilakukan permintaan pendaftaran.
- Setup Script: Bagian ini menggunakan Composition API Vue. Variabel yang dideklarasikan meliputi userData, yang merupakan variabel reaktif yang menyimpan nilai dari input formulir pendaftaran, dan confirmPassword yang merupakan variabel referensi untuk nilai konfirmasi password. Fungsi handleRegister mengatur logika untuk melakukan permintaan pendaftaran pengguna ke server saat tombol submit ditekan.
- Logika Pendaftaran: Saat tombol submit ditekan, kode akan memeriksa apakah nilai dari konfirmasi password sama dengan password yang dimasukkan sebelumnya. Jika cocok, permintaan pendaftaran dikirim ke server menggunakan fungsi tryAuth. Jika pendaftaran berhasil (berhasil diregistrasikan), variabel success menjadi true dan pesan yang diberikan oleh server akan ditampilkan sebagai message.
Kode ini bertanggung jawab untuk mengatur formulir pendaftaran, memvalidasi input, dan melakukan permintaan pendaftaran ke server. Ini memastikan bahwa password yang dimasukkan oleh pengguna dan konfirmasi password sesuai sebelum pendaftaran dilakukan.

### Code 33
Code terdapat pada vue_project/src/App.vue
```
<script setup>
import {RouterView} from 'vue-router'
import navbar from '@/components/UI/navbar.vue';
</script>

<template>
  <navbar />
  <main>
    <RouterView />
  </main>
</template>
```
Kode yang diberikan adalah sebuah komponen utama yang bertindak sebagai tata letak (layout) dari aplikasi. Berikut penjelasan singkatnya:
- Script Setup: Bagian ini menggunakan fitur script setup dari Vue 3. Dalam kasus ini, impor RouterView dari vue-router yang bertanggung jawab untuk menampilkan komponen yang sesuai dengan rute yang sedang diakses. Selain itu, komponen navbar juga diimpor untuk digunakan dalam template.
- Template: Template komponen terdiri dari elemen <navbar> dan elemen <main> yang berisi <RouterView>. <navbar> ditampilkan di bagian atas halaman dan <RouterView> menampilkan komponen yang sesuai dengan rute yang sedang diakses di dalam elemen <main>. Ini adalah pola umum dalam penggunaan Vue Router di mana <RouterView> berperan menampilkan komponen yang sesuai dengan rute yang ditentukan dalam aplikasi.
Secara keseluruhan, komponen ini bertindak sebagai tata letak dasar aplikasi dengan menampilkan navigasi (navbar) di bagian atas dan memanfaatkan <RouterView> untuk menampilkan konten yang sesuai dengan rute yang dipilih.

### Code 34
Code terdapat pada vue_project/src/main.js
```
import './assets/main.css'

import { createApp } from 'vue'
import {createPinia} from 'pinia'
import App from './App.vue'
import router from './router'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'
import VueSweetalert2 from 'vue-sweetalert2';
import 'sweetalert2/dist/sweetalert2.min.css';


const app = createApp(App)
const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)

app.use(router)
app.use(pinia)
app.mount('#app')
app.use(VueSweetalert2)
```
Kode yang diberikan adalah konfigurasi pada bagian entry point dari aplikasi Vue 3. Berikut adalah penjelasan singkat dari kode tersebut:
- import './assets/main.css': Ini merupakan impor untuk file stylesheet main.css, yang kemungkinan besar berisi gaya umum yang akan diterapkan ke seluruh aplikasi.
- import { createApp } from 'vue': Mengimpor fungsi createApp dari Vue 3 untuk membuat instansi aplikasi.
- import { createPinia } from 'pinia': Mengimpor createPinia dari Pinia, sebuah state-management library untuk Vue 3.
- import App from './App.vue': Mengimpor komponen utama App.vue yang akan menjadi root dari aplikasi Vue.
- import router from './router': Mengimpor instance dari router untuk menangani rute aplikasi.
- import piniaPluginPersistedstate from 'pinia-plugin-persistedstate': Mengimpor plugin pinia-plugin-persistedstate dari Pinia, yang memungkinkan Pinia state store untuk bertahan saat aplikasi direload.
- import VueSweetalert2 from 'vue-sweetalert2';: Mengimpor SweetAlert2, sebuah plugin untuk menampilkan alert yang lebih menarik pada aplikasi Vue. Ini termasuk file CSS SweetAlert2.
- const app = createApp(App): Membuat instansi aplikasi menggunakan fungsi createApp dari Vue, dan menjadikan komponen App.vue sebagai root dari aplikasi.
- const pinia = createPinia(): Membuat instance Pinia untuk manajemen state dan kemudian menggunakan plugin piniaPluginPersistedstate untuk membuat state Pinia bisa bertahan saat aplikasi direload.
- app.use(router): Menggunakan instance router dalam aplikasi.
- app.use(pinia): Menggunakan instance Pinia dalam aplikasi.
- app.mount('#app'): Me-mount aplikasi ke elemen HTML yang memiliki id bernama app di file HTML.
- app.use(VueSweetalert2): Menggunakan plugin SweetAlert2 dalam aplikasi.
Jadi, secara keseluruhan, kode ini mengatur konfigurasi awal aplikasi Vue 3, menggunakan router, Pinia untuk manajemen state, dan plugin SweetAlert2 untuk alert yang lebih menarik dalam aplikasi.

## Kesimpulan
Sebuah situs web Simple Twitter merupakan platform yang menyediakan beragam fitur yang mirip dengan Twitter, seperti membuat dan membagikan tweet, mengunggah foto, melihat peringkat atau leaderboard untuk tweet terpopuler, dan halaman login dan registrasi.
- Tweeting: Pengguna dapat membuat dan membagikan tweet, yang mungkin juga dapat mencakup teks, gambar, atau media lainnya.
- Unggah Foto: Kemampuan untuk mengunggah foto sebagai bagian dari tweet atau sebagai entitas terpisah.
- Leaderboard Tweet Terbanyak: Memberikan informasi tentang tweet yang paling populer atau memiliki interaksi terbanyak.
- Halaman Login dan Registrasi: Fitur otentikasi memungkinkan pengguna untuk membuat akun baru atau masuk ke dalam platform.
Dalam pengembangan situs serupa, hal-hal yang perlu dipertimbangkan termasuk desain antarmuka yang responsif, keamanan terkait privasi pengguna, manajemen database untuk menyimpan tweet dan data pengguna, serta validasi masukan pengguna untuk memastikan informasi yang masuk adalah sah. Diperlukan pula penanganan error dan pesan umpan balik yang jelas bagi pengguna.
