from werkzeug.security import generate_password_hash, check_password_hash


password = input('Enter password')
hashed_password=generate_password_hash(password, salt_length=8)
print(hashed_password)

rit = (["Durban", "Ritson",
        ["A", "B", "C1", "C3", "D1", "D3", "E1", "E2", "F", "G1", "G2", "H1", "H2", "J", "K", "L", "M", "N", "P", "Q",
         "R"],
        "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.dut.ac.za%2Fmaps%2F&psig=AOvVaw1SPFVlmHykRJY6uQS48VU_&ust=1710243762850000&source=images&cd=vfe&opi=89978449&ved=0CBMQjRxqFwoTCMjlkNKQ7IQDFQAAAAAdAAAAABAE"])
ste = (["Durban", "Steve Biko",
        ["A1", "A2", "A3", "A4", "A5", "A6", "B", "C", "D1", "D2", "D3", "D4", "D5", "D6", "E", "F1", "G1", "G2", "H",
         "J", "K", "L", "M", "N", "O", "Q", "P", "S", "R"],
        "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.dut.ac.za%2Fmaps%2F&psig=AOvVaw3EhvNxB2vrRL5cmZ9A20xS&ust=1710244376895000&source=images&cd=vfe&opi=89978449&ved=0CBMQjRxqFwoTCNijv_aS7IQDFQAAAAAdAAAAABAE"])
Ml = (["Durban", "Ml Sultan", ["A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M"],
       "https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.dut.ac.za%2Fmaps%2F&psig=AOvVaw0CxqD4WcNyrF6Fsvanya4s&ust=1710244494160000&source=images&cd=vfe&opi=89978449&ved=0CBMQjRxqFwoTCLCC266T7IQDFQAAAAAdAAAAABAE"])
