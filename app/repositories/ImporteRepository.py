from sqlalchemy import desc
from db import db
from models.Importe import Importe

class ImporteRepository:

    @staticmethod
    def get_by_season_id(season_id, session=None):
        sess = session or db.session
        return (
            sess.query(Importe)
            .filter(Importe.seasonId == season_id)
            .order_by(desc(Importe.importeDate), desc(Importe.id))
            .all()
        )

    @staticmethod
    def get_by_id(importe_id, session=None):
        sess = session or db.session
        return sess.query(Importe).get(importe_id)

    @staticmethod
    def delete_by_id(importe_id, session=None):
        sess = session or db.session
        sess.query(Importe).filter(Importe.id == importe_id).delete()
        sess.commit()

    @staticmethod
    def delete_by_season_id(season_id, session=None):
        sess = session or db.session
        sess.query(Importe).filter(Importe.seasonId == season_id).delete()
        sess.commit()
