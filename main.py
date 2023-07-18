import sys
from dataclass import Dataclass
from app import App


data = Dataclass(
    __file__=sys.argv[-1]
)

app = App(data)

app.start()
