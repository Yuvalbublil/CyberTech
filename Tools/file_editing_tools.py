import os
import time
import datetime
def set_mod_date(fileLocation,year, month, day, hour, minute, second):
    """
    this function allows you to mod the date of the file.
    :param fileLocation:
    :param year:
    :param month:
    :param day:
    :param hour:
    :param minute:
    :param second:
    :return:
    """
    date = datetime.datetime(year=year, month=month, day=day, hour=hour, minute=minute, second=second)
    modTime = time.mktime(date.timetuple())
    os.utime(fileLocation, (modTime, modTime))


def make_file_hidden(fileName):
    os.system("attrib +h " + fileName)


def make_file_unhidden(fileName):
    os.system("attrib -h " + fileName)

