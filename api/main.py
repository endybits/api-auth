from datetime import timedelta
from typing import Annotated

from fastapi import FastAPI
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm


from api.schemas import Token
from api.schemas import User
from api.utils import authenticate_user, get_current_active_user
from api.utils import create_access_token
from api.fake_db import fake_users_db
from api.sensible_data import ACCESS_TOKEN_EXPIRE

app = FastAPI()

@app.get('/')
def login():
    return "LogIn Token"

@app.post('/token', response_model=Token)
async def login_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):

    user = authenticate_user(fake_db=fake_users_db, username=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get('/users/me')
async def read_user_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


# Current active user's items
@app.get('/users/me/items')
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return {
        'item': ['item_1', 'item_2', 'item_n'],
        'owner': current_user.username
    }