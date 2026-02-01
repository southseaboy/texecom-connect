FROM python:3-alpine

WORKDIR /usr/src/app

COPY alarm-monitor.py ./
COPY texecomConnect.py ./
COPY texecomDefines.py ./
COPY area.py ./
COPY user.py ./
COPY zone.py ./
COPY hexdump.py ./

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "python", "alarm-monitor.py" ]
