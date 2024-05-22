class SmartCardSimulator:
    def __init__(self):
        self.authenticated = False
        self.data = {
            "3F00": {"description": "Master File", "contents": "Root directory"},
            "DF01": {"description": "Product Information", "contents": "This product is a high-end smartphone."},
            "DF02": {"description": "Product Information", "contents": "This product is a luxury watch."}
        }

    def connect(self):
        print("Simulated connection to smart card established.")
        return True

    def authenticate(self, pin):
        if pin == "1234":
            self.authenticated = True
            print("Authentication successful.")
        else:
            print("Authentication failed.")
        return self.authenticated

    def select_file(self, file_id):
        if file_id in self.data:
            print(f"Selected file {file_id}: {self.data[file_id]['description']}")
            return True
        else:
            print("File not found.")
            return False

    def read_file(self, file_id):
        if self.authenticated:
            if file_id in self.data:
                print(f"Reading file {file_id}: {self.data[file_id]['contents']}")
                return self.data[file_id]['contents']
            else:
                print("File not found.")
        else:
            print("Authentication required.")
        return None

# Simulate operations
smart_card = SmartCardSimulator()
smart_card.connect()

pin = input("Please enter your PIN to access the smart card: ")
if smart_card.authenticate(pin):
    file_id = input("Enter the file ID you want to access (DF01 for the first product, DF02 for the second): ")
    if smart_card.select_file(file_id):
        product_description = smart_card.read_file(file_id)
else:
    print("Access denied due to failed authentication.")
