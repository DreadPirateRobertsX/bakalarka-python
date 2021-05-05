from os import listdir, path
import analyser
from prettytable import PrettyTable


class MyTerminal:
    actual_path = "/"

    def __init__(self, output_path, case_name):
        self.output_path = output_path
        self.case_name = case_name

    def terminal_init(self):
        print("Prikazy: ls, cd, show, exit")
        print("root:" + self.actual_path + "$", end=" ")
        command = input().split(" ")

        while command[0] != "exit":
            if command[0] == "ls":
                self.listdir(command)
            elif command[0] == "cd":
                self.change_directory(command)
            elif command[0] == "show":
                self.show(command)

            print("root:" + self.actual_path + "$", end=" ")
            command = input().split(" ")
    
    def show(self, command):
        new_path = self.actual_path
        if command[1][0] == "/":
            analyser.read_file(command[1], self.output_path, self.case_name)
        else:
            if new_path == "/":
                new_path = ""
            new_path = new_path + "/" + command[1]
            analyser.read_file(new_path, self.output_path, self.case_name)

    def listdir(self, command):
        helper = 1
        if len(command) == 2:
            new_path = command[1]
            if command[1][0] != "/":
                if self.actual_path == "/":
                    self.actual_path = ""
                new_path = self.actual_path + "/" + new_path
        else:
            new_path = self.actual_path

        try:
            if not path.exists(new_path):
                print("Zadana cesta \"" + new_path + "\" neexistuje")
                return
            dirs = listdir(new_path)
        except NotADirectoryError:
            print("Zadana cesta \"" + new_path + "\" neexistuje")
            return

        for m_dir in dirs:
            print(m_dir, end="  ")
            if helper % 10 == 0:
                print("\n")
            helper += 1
        print("\n")

    def change_directory(self, command):
        if len(command) != 2:
            print("Napletny vstup pre prikaz \"cd\"")
            return
        tmp = self.actual_path

        if command[1][0] == "/":
            self.actual_path = command[1]
        elif command[1] == "..":
            command[1] = self.actual_path.split("/")
            command[1].pop()
            if len(command[1]) == 1:
                command[1] = "/"
            else:
                command[1] = "/".join(command[1])
            self.actual_path = command[1]

        else:
            if self.actual_path == "/":
                self.actual_path = ""
            self.actual_path = self.actual_path + "/" + command[1]
        if not path.exists(self.actual_path):
            print("Hladany adresar neexistuje")
            self.actual_path = tmp
