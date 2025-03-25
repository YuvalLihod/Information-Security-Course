"""
An algorithm for collision detection
"""

from prf import PRF
import random


def find_collision(f, start):
    """
    :param f: oracle for a random function
    :param start: starting point
    :return: x_0, x_1 such that x_0 != x_1 and f(x_0) = f(x_1)
    """
    #?
    prev_turtle = start
    turtle = f.calc(start)
    rabbit = f.calc(f.calc(start))
    while turtle != rabbit:
        prev_turtle = turtle
        turtle = f.calc(turtle) #move the first pointer one step
        rabbit = f.calc(f.calc(rabbit)) #move the second pointer 2 steps
    rabbit = start
    prev_rabbit = rabbit
    while turtle != rabbit:
        prev_rabbit = rabbit
        prev_turtle = turtle
        turtle = f.calc(turtle) #move the first pointer one step
        rabbit = f.calc(rabbit) #move the second pointer one step
    return prev_rabbit,prev_turtle # we might return x_0=x_1 if starting point was inside circle


def main():
    key = b'\xde\xa4\xf3l\x99~\x13\xed\xf5\x16\xe4#\xc1\xa4\xef\x04'
    block_size = 4
    f = PRF(key, block_size)
    start = 0
    while True:
        x_0, x_1 = find_collision(f, start)
        print(x_0, x_1)
        if x_0 != x_1 and f.calc(x_0) == f.calc(x_1):
            print("Success")
            break
        else:
            print("Fail")
            # What needs to be modified here so that the attack eventually succeeds?
            #?
            start = random.randint(0,pow(2,8*block_size)-1)


if __name__ == "__main__":
    main()
