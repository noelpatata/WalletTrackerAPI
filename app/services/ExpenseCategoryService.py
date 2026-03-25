from models.ExpenseCategory import ExpenseCategory
from repositories.ExpenseCategoryRepository import ExpenseCategoryRepository
from exceptions.Http import HttpException
from utils.Constants import ExpenseCategoryMessages


class ExpenseCategoryService:

    @staticmethod
    def get_by_id(category_id: int, session) -> ExpenseCategory:
        category = ExpenseCategoryRepository.get_by_id(category_id, session)
        if not category:
            raise HttpException(ExpenseCategoryMessages.NOT_FOUND, 200)
        return category

    @staticmethod
    def get_all(session) -> list:
        return ExpenseCategoryRepository.get_all(session)

    @staticmethod
    def create(name: str, session, sort_order: int = None) -> ExpenseCategory:
        new_category = ExpenseCategory(name=name, sortOrder=sort_order)
        new_category.save(session)
        return new_category

    @staticmethod
    def delete_by_id(category_id: int, session) -> None:
        ExpenseCategoryRepository.delete_by_id(category_id, session)

    @staticmethod
    def edit_name(category_id: int, name: str, session) -> ExpenseCategory:
        category = ExpenseCategoryRepository.get_by_id(category_id, session)
        if not category:
            raise HttpException(ExpenseCategoryMessages.NOT_FOUND, 200)
        category.setName(name)
        category.save(session)
        return category
