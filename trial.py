def calc(**kwargs):
    print(kwargs)
    if kwargs['add']==3:
        print("hello")


calc(add=3, multiply=5)
