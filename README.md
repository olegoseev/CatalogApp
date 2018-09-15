## CatalogApp
CatalogApp is a simple catalog web application that provides a list of items within a variety of categories. Registered user can add, modify, or delete item information. Users can modify only those items that they themselves have created.


### Requirements
* Python 3.5 and above
* Flask 1.0.2
* SqlAlchemy 1.2.10

### Setup

CatalogApp is using SQLite database to store the data. The database must be initialized before the first run by executing command **python3 database_setup.py**. A sample of CatalogApp database content is provided. The first registered user will be able to modify or delete sample records.

### Usage

To launch CatalogApp web application execute command **python3 catalogapp.py**. After a web server has launched the application will be accessible by visiting **http://localhost:8000** locally on your browser.
The application provides database snapshot in JSON format at **http://localhost:8000/catalog.json**.

### License

This project is licensed under the terms of the MIT license.
