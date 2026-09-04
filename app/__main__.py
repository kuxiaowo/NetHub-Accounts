from . import create_app

app = create_app()


if __name__ == "__main__":
    app.run(host=app.config["ACCOUNTS_HOST"], port=app.config["ACCOUNTS_PORT"])
