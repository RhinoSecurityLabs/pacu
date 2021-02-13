from utils import stringify_datetime


class ModelUpdateMixin():

    def update(self, database, commit=True, **kwargs):
        """ Instead of requiring three lines to update a single field inside
        a database session, this method updates a single field in one line.

        Example usage:
            session.update(database, field_name={'json': ...}) """

        for key, value in kwargs.items():
            value = stringify_datetime(value)
            setattr(self, key, value)

        database.add(self)

        if commit:
            database.commit()
