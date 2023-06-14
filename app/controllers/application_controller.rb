require "jwt"

class ApplicationController < ActionController::API
    before_action :authenticate_user

    SECRET_KEY = Rails.application.secrets.secret_key_base.to_s
    
    def jwt_encode(payload, exp= 7.days.from_now)
        payload[:exp] = exp.to_i
        JWT.encode(payload, SECRET_KEY)
    end

    def jwt_decode(token)
        decoded = JWT.decode(token, SECRET_KEY)[0]
        HashWithIndifferentAccess.new decoded
    end
    
    private
    def authenticate_user
        header = request.headers["Authorization"]
        header = header.split(" ").last if header
        begin
            @decoded = self.jwt_decode(header)
            @current_user = User.find(@decoded[:user_id])
        rescue ActiveRecord::RecordNotFound => e
            render json: {errors: e.message}, status: :unauthorized
        rescue JWT::DecodeError => e
            render json: {errors: e.message}, status: :unauthorized
        end
    end
end