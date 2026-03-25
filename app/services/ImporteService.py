from models.Importe import Importe
from repositories.ImporteRepository import ImporteRepository
from repositories.SeasonRepository import SeasonRepository
from exceptions.Http import HttpException
from utils.Constants import ImporteMessages, SeasonMessages


class ImporteService:

    @staticmethod
    def get_by_season(season_id: int, session) -> list:
        return ImporteRepository.get_by_season_id(season_id, session)

    @staticmethod
    def get_by_id(importe_id: int, session) -> Importe:
        importe = ImporteRepository.get_by_id(importe_id, session)
        if not importe:
            raise HttpException(ImporteMessages.NOT_FOUND, 200)
        return importe

    @staticmethod
    def create(concept: str, importe_date: str, amount: float, balance_after: float, season_id: int, session) -> Importe:
        season = SeasonRepository.get_by_id(season_id, session)
        if not season:
            raise HttpException(SeasonMessages.NOT_FOUND, 200)

        new_importe = Importe(
            concept=concept,
            importeDate=importe_date,
            amount=amount,
            balanceAfter=balance_after,
            seasonId=season_id
        )
        new_importe.save(session)
        return new_importe

    @staticmethod
    def create_bulk(importes_data: list, session) -> list:
        seasons_cache = {}
        created = []

        for item in importes_data:
            season_id = item.get('seasonId')
            if season_id not in seasons_cache:
                season = SeasonRepository.get_by_id(season_id, session)
                if not season:
                    raise HttpException(SeasonMessages.NOT_FOUND, 200)
                seasons_cache[season_id] = season

            importe = Importe(
                concept=item.get('concept'),
                importeDate=item.get('importeDate'),
                amount=item.get('amount'),
                balanceAfter=item.get('balanceAfter'),
                seasonId=season_id
            )
            session.add(importe)
            created.append(importe)

        session.commit()
        return created

    @staticmethod
    def delete_by_id(importe_id: int, session) -> None:
        ImporteRepository.delete_by_id(importe_id, session)

    @staticmethod
    def delete_by_season(season_id: int, session) -> None:
        ImporteRepository.delete_by_season_id(season_id, session)
