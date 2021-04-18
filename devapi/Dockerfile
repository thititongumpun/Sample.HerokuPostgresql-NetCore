  
FROM mcr.microsoft.com/dotnet/sdk:5.0-buster-slim as build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:5.0.0-alpine3.12
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT [ "dotnet", "devapi.dll" ]