from sqlalchemy import orm

from pacu.utils import stringify


class ModelUpdateMixin:
    def update(self, database: orm.session.Session, commit: bool = True, **kwargs) -> None:
        """ Instead of requiring three lines to update a single field inside
        a database session, this method updates a single field in one line.

        Example usage:
            session.update(database, field_name={'json': ...}) """

        for key, value in kwargs.items():
            value = stringify(value)
            setattr(self, key, value)

        database.add(self)

        if commit:
            database.commit()
