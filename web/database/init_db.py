import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), 'truyenhay.db')

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create the 'users' table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT   UNIQUE,
            password TEXT  ,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create the 'truyen' table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS truyen (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT  ,
            author TEXT  ,
            category TEXT  ,
            description TEXT,
            image TEXT,
            views INTEGER DEFAULT 0,
            status TEXT   DEFAULT "Đang ra",
            create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create the 'Comments' table
    cursor.execute('''
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            truyen_id INTEGER  ,
            username TEXT  ,
            content TEXT  ,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (truyen_id) REFERENCES truyen(id)
        )
    ''')


    # Create the 'Log dang nhap' table
    cursor.execute('''
        CREATE TABLE login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT  ,
            ip_address TEXT,
            success INTEGER,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Du lieu bang users
    cursor.execute('''
        INSERT INTO users (username, password, email, role) VALUES
        ("admin", "admin@123", "admin@truyenhay.local", "admin"),
        ("hieu", "hieu@123", "hieu@truyenhay.local", "user"),
        ("hai", "hai@123", "hai@truyenhay.local", "user"),
        ("duy", "duy@123", "duy@truyenhay.local", "user"),
        ("thanh", "thanh@123", "thanh@truyenhay.local", "user")
    ''')

    # Du lieu bang truyen
    truyen_data = [
        (
            "Tiên Nghịch",
            "Nhĩ Căn",
            "Tiên Hiệp",
            ''' tiểu thuyết “Tiên Nghịch” của tác giả Nhĩ Căn, kể về thiếu niên bình phàm Vương Lâm 
            xuất thân nông thôn, mang theo nhiệt huyết, tu luyện nghịch tiên, không chỉ cầu trường 
            sinh, mà còn muốn thoát khỏi thân phận giun dế. Hắn tin rằng đạo do người quyết định, 
            dùng tư chất bình phàm bước vào con đường tu chân, trải qua bao phong ba bão táp, 
            dựa vào trí tuệ sáng suốt, từng bước một bước lên đỉnh cao, dựa vào sức một người, 
            danh chấn Tu chân giới.''',
            "tien_nghich.jpg",
            24124,
            "Hoàn thành",
        ),
        (
            "Phàm Nhân Tu Tiên",
            "Vong Ngữ",
            "Tiên Hiệp",
            "Hàn Lập, một thiếu niên xuất thân bần hàn, tình cờ bước vào con "
            "đường tu tiên đầy chông gai. Không có tiên căn, không có kỳ "
            "ngộ lớn lao, chỉ có sự cẩn thận và kiên trì đưa hắn đi đến đỉnh "
            "cao.",
            "pham_nhan_tu_tien.jpg",
            22412,
            "Hoàn thành",
        ),
        (
            "Quang Âm Chi Ngoại",
            "Nhĩ Căn",
            "Tiên Hiệp",
            '''Trời đất là quán trọ của muôn vật và chúng sinh, thời gian là kẻ qua đường của xưa và nay. 
            Gương mặt tàn khuyết mở ra con mắt quỷ dị, nơi ánh nhìn chiếu tới thì sinh linh lầm than, biến thành vùng cấm vĩnh hằng. 
            Dưới tận thế tàn khốc ấy, con người chẳng khác gì cỏ rơm. Thiếu niên Hứa Thanh vì sinh tồn mà tiến bước bằng sự tàn nhẫn và quyết liệt.''',
            "quang_am_chi_ngoai.jpg",
            19284,
            "Đang ra",
        ),
        (
            "Thôn Phệ Tinh Không",
            "Ngã Cật Tây Hồng Thị",
            "Hiện Đại",
            '''Một ngày nọ, thế giới xuất hiện loại virus RR không rõ lai lịch, cuốn thế giới vào thảm hoạ. Động vật bị truyền nhiễm đột biến thành quái thú đáng sợ, xâm lược với số lượng lớn. Trong lúc loài người đối mặt với diệt vong, họ đã xây lên bức tường bao vây, thành lập căn cứ làm pháo đài cuối cùng bảo vệ con người. 
            Trong thời gian này, con người nếm trải đủ mọi khó khăn, được gọi là “thời kỳ Đại Niết Bàn”. Trong môi trường sinh tồn cực đoan, bản năng của con người cũng dần phát triển, ngọn gió thượng võ phất lên, tố chất cơ thể con người vượt trội hơn trước. Mà trong những người xuất sắc, được gọi là “chiến binh”. La Phong năm 18 tuổi cũng ước mơ trở thành một trong số họ. Cậu lúc này sắp phải thi đại học, đang đối diện với sự lựa chọn giữa ngã tư đời người. Nhưng lại bị quái thú tấn công ảnh hưởng quỹ đạo cuộc đời của cậu hết lần này đến lần khác. 
            Dưới uy hiếp của quái thú, cư dân trong thành phố đối diện với nguy hiểm, quân sự lại bó tay. Duy chỉ có chiến binh xông pha, bảo vệ an toàn cho căn cứ. La Phong được những chiến binh truyền cảm hứng, âm thầm hạ quyết tâm trở thành chiến binh bảo vệ người mình yêu thương. Đây chính là khởi đầu của mọi thứ, khởi điểm của  con đường chiến binh La Phong, cũng vén bức màn cuộc đời truyền kì của cậu. La Phong lập chí trở thành chiến binh. Con đường phía không dễ dàng, đầu tiên cậu phải đối diện với môi trường ngoại bộ, vô hình chung càng thêm ảnh hưởng tới cậu. Gia đình La Phong có điều kiện không tốt, cuộc sống túng thiếu, bố mẹ không thể giúp đỡ cậu được nhiều, cậu đành dựa vào nỗ lực của bản thân. 
            Cuối cùng, dưới sự khổ luyện, La Phong không ngừng khai quật ra tiềm năng của mình, nhận được sự nâng cấp năng lực với sự công nhận giá trị bản thân. Không những vậy, La Phong còn gánh vác gánh nặng nuôi dưỡng  gia đình, cũng vì bảo vệ tổ quốc loài người, vì cuộc sống sinh tồn và phát triển tốt hơn của con người. Cùng với những chiến binh chính nghĩa khác, liên minh đối phó quái thú hung ác. Dưới tình cảnh tận thế, La Phong cùng với những chiến binh khác liệu có thể đẩy lùi quái thú, thành công bảo vệ thế giới loài người?''',
            "thon_phe_tinh_khong.jpg",
            18903,
            "Hoàn thành",
        ),
        (
            "Mục Thần Ký",
            "Trạch Trư",
            "Tiên Hiệp",
            '''Trong Đại Khư Tàn Lão Thôn, nơi cư ngụ của chín vị lão nhân bí ẩn, có một thiếu niên tên Tần Mục do họ nuôi dưỡng từ nhỏ. Một ngày nọ, con bò mẹ mà Tần Mục chăn dắt bỗng cất tiếng nói tiếng người, từ đó cậu càng nhận ra sự nguy hiểm và huyền bí của vùng đất Đại Khư – nơi bị thần linh bỏ rơi. Ở đây, ma thần xuất hiện trong bóng tối, xương cốt của thần linh múa may trên những tàn tích, xương rồng bảo vệ con, và những con thuyền khổng lồ kéo mặt trời di chuyển… Dù đối diện với bao hiểm nguy, Tần Mục vẫn không hề nao núng, lĩnh hội và dung hòa tất cả những gì chín vị lão truyền dạy, lấy thân bá thể mà khai phá một vùng trời riêng.''',
            "muc_than_ky.jpg",
            16903,
            "Đang ra",
        ),
        (
            "Thương nguyên đồ",
            "Ngã Cật Tây Hồng Thị",
            "Tiên hiệp",
            '''Nói về yêu tà hoành hành ở Thương Nguyên giới, loài người chịu đủ tàn phá, nam chính Mạnh Xuyên từ nhỏ đã lập lời thề phải báo thù cho mẫu thân. Lấy đạo viện Kính Hồ làm khởi điểm, dựa vào tâm chí kiên nghị không sợ hãi và thân thủ đao pháp nhanh nhạt, trừng phạt gian ác, tiêu diệt yêu tộc, đăng đỉnh tứ đại đạo viện, nổi danh Đông Minh phủ, bái Thượng Nguyên Sơ Sơn, trở thành một Thần Ma.''',
            "thuong_nguyen_do.jpg",
            15460,
            "Đang ra",
        )
    ]

    cursor.executemany('''
    INSERT INTO truyen (title, author, category, description, image, views, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)''', truyen_data
    )
   
    conn.commit()
    conn.close()
    print("Database initialized succesfully")

if __name__ == "__main__":
    init_db()