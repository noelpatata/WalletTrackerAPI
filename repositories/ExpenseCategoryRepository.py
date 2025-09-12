from sqlalchemy import func
from db import db
from models.ExpenseCategory import ExpenseCategory
from models.Expense import Expense

class ExpenseCategoryRepository:

    @staticmethod
    def get_by_id(category_id, session=None):
        sess = session or db.session

        category = sess.query(ExpenseCategory).get(category_id)
        if not category:
            return None

        total = (
            sess.query(func.sum(Expense.price))
            .filter(Expense.category == category.id)
            .scalar()
        ) or 0.0

        category.setTotal(total)
        return category
        
    @staticmethod
    def get_all(session=None):
        sess = session or db.session
        categories = sess.query(ExpenseCategory).order_by(
            ExpenseCategory.sortOrder.asc().nullsfirst(),
            ExpenseCategory.id
        ).all()

        for category in categories:
            total = (
                sess.query(func.sum(Expense.price))
                .filter(Expense.category == category.id)
                .scalar()
            ) or 0.0
            category.setTotal(total)

        return categories

    
    @staticmethod
    def delete_by_id(category_id, session=None):
        sess = session or db.session
        sess.query(ExpenseCategory).filter(ExpenseCategory.id == category_id).delete()
        sess.commit()
