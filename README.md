Принимает вебхук от куба при успешном сканировании, после чего по апи идет за отчетом скана проекта
CI сканирует проект указав properties через свои переменные

```
sudo docker build -t sonarqube-adapter .
```

Можно прописать всё в манифесте для ис
```
sudo docker run -d \                    
  --name sonarqube-adapter \
  --network dd-net \
  -p 8000:8000 \
  -e DD_URL="http://host:port" \
  -e DD_TOKEN="TOKEN" \
  -e GIT_DOMAIN="priorbank.gitlab.com" \
  -e SONAR_URL="http://sonarqube:9000" \
  -e SONAR_TOKEN="TOKEN" \
  sonarqube-adapter
```


В джобе может выглядеть так:

```
sonar-scanner \
  -Dsonar.analysis.project_path="${CI_PROJECT_NAMESPACE}/${CI_PROJECT_NAME}" \ 
  -Dsonar.analysis.branch="${CI_COMMIT_REF_NAME}" \ 
  -Dsonar.analysis.commit_sha="${CI_COMMIT_SHA}"
```
