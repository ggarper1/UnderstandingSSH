class Logs():

    @staticmethod
    def error(msg:str, additional:str=""):
        raise Exception(f"\n{msg}\n\t{additional}")