import hashlib
import tkinter as tk
from tkinter import messagebox, Listbox, END, simpledialog

class Block:
    def __init__(self, data, previous_hash):
        self.hash = hashlib.sha256()
        self.previous_hash = previous_hash
        self.nonce = 0
        self.data = data

    def mine(self, difficulty):
        target = 2 ** (256 - difficulty)
        while True:
            self.hash = hashlib.sha256()
            self.hash.update(str(self).encode("utf-8"))
            if int(self.hash.hexdigest(), 16) < target:
                break
            self.nonce += 1

    def __str__(self):
        return f"{self.previous_hash.hexdigest()}{self.data}{self.nonce}"


class Chain:
    def __init__(self, difficulty):
        self.difficulty = difficulty
        self.blocks = []
        self.pool = []
        self.create_origin_block()

    def proof_of_work(self, block):
        hash_obj = hashlib.sha256()
        hash_obj.update(str(block).encode("utf-8"))
        return (
            block.hash.hexdigest() == hash_obj.hexdigest()
            and int(hash_obj.hexdigest(), 16) < 2 ** (256 - self.difficulty)
            and block.previous_hash == self.blocks[-1].hash
        )

    def add_to_chain(self, block):
        if self.proof_of_work(block):
            self.blocks.append(block)

    def add_to_pool(self, data):
        self.pool.append(data)

    def create_origin_block(self):
        h = hashlib.sha256()
        h.update("".encode("utf-8"))
        origin = Block("Origin", h)
        origin.mine(self.difficulty)
        self.blocks.append(origin)

    def mine(self):
        if len(self.pool) > 0:
            data = self.pool.pop()
            block = Block(data, self.blocks[-1].hash)
            block.mine(self.difficulty)
            self.add_to_chain(block)


class VotingApp:
    def __init__(self):
        self.chain = Chain(20)
        self.parties = {"Congress": 0, "BJP": 0}
        self.serial_numbers = set()
        self.admin_password = "admin123"  # Default password for administrative actions

        self.root = tk.Tk()
        self.root.title("Blockchain Voting System")
        self.root.configure(bg="#f0f8ff")
        self.root.geometry("1920x1080")
        self.create_widgets()

    def create_widgets(self):
        container = tk.Frame(self.root, bg="#f0f8ff")
        container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        header = tk.Label(container, text="Blockchain Voting System", font=("Helvetica", 32, "bold"), bg="#f0f8ff", fg="#4b0082")
        header.grid(row=0, column=0, columnspan=2, pady=20)

        tk.Label(container, text="Enter Your Serial Number:", bg="#f0f8ff", font=("Helvetica", 16)).grid(row=1, column=0, padx=20, pady=10, sticky=tk.W)
        self.serial_var = tk.StringVar()
        tk.Entry(container, textvariable=self.serial_var, font=("Helvetica", 14)).grid(row=1, column=1, padx=20, pady=10)

        tk.Label(container, text="Enter Your Name:", bg="#f0f8ff", font=("Helvetica", 16)).grid(row=2, column=0, padx=20, pady=10, sticky=tk.W)
        self.name_var = tk.StringVar()
        tk.Entry(container, textvariable=self.name_var, font=("Helvetica", 14)).grid(row=2, column=1, padx=20, pady=10)

        tk.Button(container, text="Vote", command=self.cast_vote, bg="#32cd32", fg="white", font=("Helvetica", 14, "bold"), width=15).grid(row=3, column=1, pady=10)

        self.party_listbox = Listbox(container, bg="#e6e6fa", selectbackground="#9370db", font=("Helvetica", 14), height=5, width=30)
        self.party_listbox.grid(row=4, column=1, pady=10)
        for party in self.parties.keys():
            self.party_listbox.insert(END, party)

        tk.Button(container, text="Show Results", command=self.show_results, bg="#ffa07a", fg="white", font=("Helvetica", 14, "bold"), width=15).grid(row=5, column=1, pady=10)
        tk.Button(container, text="Add Party", command=self.add_party, bg="#4682b4", fg="white", font=("Helvetica", 14, "bold"), width=15).grid(row=6, column=0, pady=10)
        tk.Button(container, text="Remove Party", command=self.remove_party, bg="#b22222", fg="white", font=("Helvetica", 14, "bold"), width=15).grid(row=6, column=1, pady=10)

    def cast_vote(self):
        serial_number = self.serial_var.get()
        name = self.name_var.get()
        selected_party = self.party_listbox.get(self.party_listbox.curselection()) if self.party_listbox.curselection() else None

        if not serial_number.isdigit() or not name.strip() or not selected_party:
            messagebox.showerror("Error", "Please enter valid details and select a party.")
            return

        serial_number = int(serial_number)

        if serial_number in self.serial_numbers:
            messagebox.showerror("Error", "This serial number has already voted.")
            return

        self.parties[selected_party] += 1
        self.chain.add_to_pool((name, serial_number, selected_party))
        self.chain.mine()
        self.serial_numbers.add(serial_number)

        messagebox.showinfo("Success", f"Vote cast for {selected_party} by {name}.")
        self.serial_var.set("")
        self.name_var.set("")

    def add_party(self):
        password = self.get_password()
        if password != self.admin_password:
            messagebox.showerror("Error", "Invalid password.")
            return

        party_name = simpledialog.askstring("Add Party", "Enter party name:")
        if party_name and party_name.strip() and party_name not in self.parties:
            self.parties[party_name.strip()] = 0
            self.party_listbox.insert(END, party_name.strip())
            messagebox.showinfo("Success", f"Party '{party_name}' added.")
        else:
            messagebox.showerror("Error", "Invalid or duplicate party name.")

    def remove_party(self):
        password = self.get_password()
        if password != self.admin_password:
            messagebox.showerror("Error", "Invalid password.")
            return

        selected_party = self.party_listbox.get(self.party_listbox.curselection()) if self.party_listbox.curselection() else None
        if selected_party and selected_party in self.parties:
            self.parties.pop(selected_party)
            self.party_listbox.delete(self.party_listbox.curselection())
            messagebox.showinfo("Success", f"Party '{selected_party}' removed.")
        else:
            messagebox.showerror("Error", "Select a valid party to remove.")

    def get_password(self):
        return simpledialog.askstring("Password", "Enter admin password:", show='*')

    def show_results(self):
        results = "\n".join([f"{party}: {votes}" for party, votes in self.parties.items()])
        messagebox.showinfo("Voting Results", results)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = VotingApp()
    app.run()


#password admin123