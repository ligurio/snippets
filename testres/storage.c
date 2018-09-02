/* http://zetcode.com/db/sqlitec/ */

#include <sqlite3.h>
#include <stdio.h>

int db_setup(sqlite3 *db);
int db_print(sqlite3 *db);
int db_add_report(sqlite3 *db);
int db_add_suite(sqlite3 *db);
int db_add_test(sqlite3 *db);

int callback(void *, int, char **, char **);

int main(void) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open("test.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    db_setup(db);

    sqlite3_close(db);
    return 0;
}

int db_setup(sqlite3 *db) {

    char *sql = "DROP TABLE IF EXISTS tests;"
                "DROP TABLE IF EXISTS suites;"
                "DROP TABLE IF EXISTS reports;"
                "CREATE TABLE tests(id INT, suite_id INT, name TEXT);"
                "CREATE TABLE suites(id INT, report_id INT, name TEXT);"
                "CREATE TABLE reports(id INT);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        return 1;
    }

    return 0;
}

int db_print(sqlite3 *db) {

    char *sql = "SELECT name FROM sqlite_master WHERE type='table'";
    rc = sqlite3_exec(db, sql, callback, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        fprintf(stderr, "Cannot open database: %s\n",
                sqlite3_errmsg(db));
        fprintf(stderr, "Failed to select data\n");
        return 1;
    }

    return 0;
}

int callback(void *NotUsed, int argc, char **argv,
                    char **azColName) {
    NotUsed = 0;
    for (int i = 0; i < argc; i++) {
        printf("%s\n", argv[i] ? argv[i] : "NULL");
    }
    return 0;
}
