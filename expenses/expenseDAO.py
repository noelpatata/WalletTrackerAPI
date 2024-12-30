from datetime import date
from sqlalchemy.orm.exc import NoResultFound
from . import expenseModel


def getAll():
    expenses = expenseModel.Expense.query.all()
    return expenses

def getByCategory(catid):
    expenses = expenseModel.Expense.query.filter(expenseModel.Expense.category == catid).all()  # Filtra los registros por precio mayor a 'price'
    return expenses

def update_expense(expense_id, new_data):
    try:
        expense = expenseModel.Expense.query.filter_by(_id=expense_id).one()  # Filtra por ID y obtiene el primero
        expense.price = new_data.get('price', expense.price)  # Actualiza solo los campos proporcionados
        expense.expenseDate = new_data.get('expenseDate', expense.expenseDate)
        expense.category = new_data.get('category', expense.category)

        expenseModel.db.session.commit()  # Guarda los cambios en la base de datos

        return expense
    except NoResultFound:
        return None  # Si no se encuentra el registro
    
