import sys
import MySQLdb as mdb
import config
import logging

logger = logging.getLogger('SecurityMetricIDS')


def check_database():
    try:
        connection = mdb.connect(config.db_connection, config.db_user, config.db_pass)
        logger.info("Checking if selected {} database exists and it is available".format(config.db_name))
        with connection:
            c = connection.cursor()
            c.execute("SHOW DATABASES LIKE '{}'".format(config.db_name))
            output = c.fetchone()
            if not output:
                try:
                    logger.info("Database not found, creating new blank one.")
                    c.execute("CREATE DATABASE {}".format(config.db_name))
                    c.execute("USE {}".format(config.db_name))

                    for line in open('database.sql'):
                        logger.info("Executing sql command: {}".format(line))
                        c.execute(line)
                    logger.info("New database successfully created")

                except Exception as detail:
                    logger.error("Error during creation of database: {}".format(detail))
                    sys.exit(1)
            else:
                logger.info("Database check completed. Database is found.")
    except Exception as dbError:
        logger.error("Unable to connect to database: {}".format(dbError))
        sys.exit(1)


def init_db_connection():
    try:
        connection = mdb.connect(config.db_connection, config.db_user, config.db_pass, config.db_name)
        connection.autocommit(True)
        return connection
    except mdb.Error, e:
        logger.error("Unable to connect to database {}".format(e))
        sys.exit(1)