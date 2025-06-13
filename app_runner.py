## @file app_runner.py
#  @brief Główna jednostka uruchamiająca aplikację GUI do podpisu cyfrowego.
from gui import SignatureInterface

## @brief Punkt wejścia aplikacji.
#  Tworzy i uruchamia interfejs użytkownika.
if __name__ == "__main__":
    app = SignatureInterface()
    app.mainloop()
