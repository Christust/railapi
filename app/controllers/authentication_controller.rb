class AuthenticationController < ApplicationController
    skip_before_action :authenticate_user

    def login
        @user = User.find_by_email(params[:email])
        if @user&.authenticate(params[:password])
            token = self.jwt_encode({user_id: @user.id})
            time = Time.now + 24.hours.to_i
            render json: {token: token, exp: time.strftime("%m-%d-%Y %H:%M"), username: @user.user_name}, status: :ok
        else
            render json: {errors: "unauthorized"}, status: :unauthorized
        end
    end
end
