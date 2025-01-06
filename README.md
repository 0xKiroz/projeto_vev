# Projeto VEV
Este é um projeto desenvolvido como parte da disciplina de **Verificação e Validação de Software**.

---

## Configuração do Ambiente de Desenvolvimento

### Clonar o Repositório

Para começar, clone o repositório do projeto:

```bash
git clone https://github.com/0xKiroz/projeto_vev.git
cd projeto_vev
```


### Criar e Ativar o Ambiente Virtual

Crie um ambiente virtual para gerenciar as dependências do projeto:

#### No Linux/MacOS:
```bash
python3 -m venv env
source env/bin/activate
```

#### No Windows:
```cmd
python -m venv env
env\Scripts\activate.bat
```

### Instalar as Dependências

Com o ambiente virtual ativado, instale todas as dependências listadas no arquivo `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## Executar o Projeto

Para iniciar o servidor de desenvolvimento, execute o seguinte comando no diretório do projeto:
```bash
python3 manage.py runserver
```

> Se estiver utilizando Windows, use `python` em vez de `python3`.
> O servidor estará disponível em http://127.0.0.1:8000/.

## Notas Adicionais

1. Certifique-se de estar utilizando a versão correta do Python (preferencialmente >= 3.8).
2. Caso precise criar um banco de dados inicial, execute as migrações:
```bash
python manage.py makemigrations
python manage.py migrate
```

3. Para criar um superusuário (acesso ao painel administrativo do Django):
```bash
python manage.py createsuperuser
```
