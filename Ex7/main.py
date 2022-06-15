
def get_file_content() -> bytes:
    """
    This function returns the current file contents
    :return: the string of this python file
    """
    with open(__file__, 'rb') as f:
        return f.read()
