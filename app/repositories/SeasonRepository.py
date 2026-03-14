from sqlalchemy import desc
from db import db
from models.Season import Season

class SeasonRepository:

    @staticmethod
    def get_all(session=None):
        sess = session or db.session
        return sess.query(Season).order_by(desc(Season.year), desc(Season.month)).all()

    @staticmethod
    def get_by_id(season_id, session=None):
        sess = session or db.session
        return sess.query(Season).get(season_id)

    @staticmethod
    def get_by_year_month(year, month, session=None):
        sess = session or db.session
        return sess.query(Season).filter(Season.year == year, Season.month == month).first()

    @staticmethod
    def get_or_create(year, month, session=None):
        sess = session or db.session
        existing = sess.query(Season).filter(Season.year == year, Season.month == month).first()
        if existing:
            return existing
        new_season = Season(year=year, month=month)
        new_season.save(sess)
        return new_season

    @staticmethod
    def delete_by_id(season_id, session=None):
        sess = session or db.session
        sess.query(Season).filter(Season.id == season_id).delete()
        sess.commit()
