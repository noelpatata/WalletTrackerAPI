from models.Season import Season
from repositories.SeasonRepository import SeasonRepository
from exceptions.Http import HttpException
from utils.Constants import SeasonMessages


class SeasonService:

    @staticmethod
    def get_all(session) -> list:
        return SeasonRepository.get_all(session)

    @staticmethod
    def get_by_id(season_id: int, session) -> Season:
        season = SeasonRepository.get_by_id(season_id, session)
        if not season:
            raise HttpException(SeasonMessages.NOT_FOUND, 200)
        return season

    @staticmethod
    def get_or_create(year: int, month: int, session) -> Season:
        return SeasonRepository.get_or_create(year, month, session)

    @staticmethod
    def delete_by_id(season_id: int, session) -> None:
        SeasonRepository.delete_by_id(season_id, session)
