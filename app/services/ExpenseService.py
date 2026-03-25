from datetime import datetime
from models.Expense import Expense
from repositories.ExpenseRepository import ExpenseRepository
from repositories.SeasonRepository import SeasonRepository
from exceptions.Http import HttpException
from utils.Constants import ExpenseMessages


class ExpenseService:

    @staticmethod
    def get_by_id(expense_id: int, session) -> Expense:
        expense = ExpenseRepository.get_by_id(expense_id, session)
        if not expense:
            raise HttpException(ExpenseMessages.NOT_FOUND, 200)
        return expense

    @staticmethod
    def get_by_category(category_id: int, session) -> list:
        return ExpenseRepository.get_by_category(category_id, session)

    @staticmethod
    def get_by_season(season_id: int, session) -> list:
        return ExpenseRepository.get_by_season(season_id, session)

    @staticmethod
    def create(price: float, expense_date: str, category_id: int, description: str, session) -> Expense:
        parsed_date = datetime.strptime(expense_date, "%Y-%m-%d")
        season = SeasonRepository.get_or_create(parsed_date.year, parsed_date.month, session)

        new_expense = Expense(
            price=price,
            category=category_id,
            expenseDate=expense_date,
            description=description,
            seasonId=season.id
        )
        new_expense.save(session)
        return new_expense

    @staticmethod
    def delete_all(session) -> None:
        ExpenseRepository.delete_all(session)

    @staticmethod
    def delete_by_id(expense_id: int, session) -> None:
        ExpenseRepository.delete_by_id(expense_id, session)

    @staticmethod
    def edit(expense_id: int, data: dict, session) -> Expense:
        expense = ExpenseRepository.get_by_id(expense_id, session)
        if not expense:
            raise HttpException(ExpenseMessages.NOT_FOUND, 200)

        expense.edit(**data)

        if data.get('expenseDate'):
            parsed_date = datetime.strptime(data.get('expenseDate'), "%Y-%m-%d")
            season = SeasonRepository.get_or_create(parsed_date.year, parsed_date.month, session)
            expense.seasonId = season.id

        expense.save(session)
        return expense
