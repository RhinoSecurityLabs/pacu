import os


# Meaningful values: 'minimal', 'low', 'high', 'extreme'
# 'Minimal' will only add tracebacks to error log files.
# 'Low' will also add data from the current PacuSession, with its
# secret_access_key field censored. This data includes all gathered AWS data.
# 'High' and 'extreme' will dump all global and local data in the most recent
# two stack frames, and in all stack frames, respectively, of every traceback.
# This data will include any information about your local file system and
# execution environment that Python has loaded into global and local variables
# at the time an error is written to the logs. Use with extreme caution.
ERROR_LOG_VERBOSITY = 'minimal'


DATABASE_FILE_PATH = os.path.join(os.getcwd(), 'sqlite.db')

if os.path.isabs(DATABASE_FILE_PATH):
    DATABASE_CONNECTION_PATH = 'sqlite:///' + DATABASE_FILE_PATH
else:
    DATABASE_CONNECTION_PATH = 'sqlite://' + DATABASE_FILE_PATH
