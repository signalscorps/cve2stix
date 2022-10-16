"""
Miscellaneous helper functions
"""

def get_date_string_nvd_format(date):
    return date.strftime("%Y-%m-%dT%H:%M:%S:%f")[:-3] + " Z"