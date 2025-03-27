import pytest
from sqlalchemy import MetaData


@pytest.fixture
def metadata():
    return MetaData()
