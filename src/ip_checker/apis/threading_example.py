import threading


def prin_cube(num: int) -> str:
    return f"Cube: {num * num * num}"


def print_square(num: int) -> str:
    return f"Square: {num * num}"


if __name__ == "__main__":
    thread1 = threading.Thread(target=print_square, args=(10,))
    thread2 = threading.Thread(target=prin_cube, args=(10,))
    print(type(thread1))

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    print("Doneee")
