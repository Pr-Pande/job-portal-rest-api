package services

import (
	"context"
	"errors"
	"job-portal-api/internal/models"
	"job-portal-api/internal/repository"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

func TestService_CreateUser(t *testing.T) {
	type args struct {
		ctx      context.Context
		userData models.NewUser
	}
	tests := []struct {
		name         string
		args         args
		want         models.User
		wantErr      bool
		mockResponse func() (models.User, error)
	}{
		{
			name: "error from the datadbase",
			args: args{
				ctx: context.Background(),
				userData: models.NewUser{
					Name:     "abhishek",
					Email:    "abhishek@gmail.com",
					Password: "12398",
				},
			},
			want:    models.User{},
			wantErr: true,
			mockResponse: func() (models.User, error) {
				return models.User{}, errors.New("erroe in hashing the password")
			},
		},
		{
			name: "success from database",
			args: args{
				ctx: context.Background(),
				userData: models.NewUser{
					Name:     "abhishek",
					Email:    "abhishek@gmail.com",
					Password: "12398",
				},
			},
			want: models.User{
				Name:  "abhishek",
				Email: "abhishek@gmail.com",
				// Password: "",
			},
			wantErr: false,
			mockResponse: func() (models.User, error) {
				return models.User{
					Name:  "abhishek",
					Email: "abhishek@gmail.com",
				}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := gomock.NewController(t)
			mockRespo := repository.NewMockUserRepo(mc)
			mockRespo.EXPECT().CreateUser(gomock.Any()).Return(tt.mockResponse()).AnyTimes()
			s, err := NewService(mockRespo)
			if err != nil {
				t.Errorf("error in initializing the repo layer")
				return
			}
			got, err := s.CreateUser(tt.args.ctx, tt.args.userData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Service.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Service.CreateUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_UserLogin(t *testing.T) {
	type args struct {
		ctx      context.Context
		email    string
		password string
	}
	tests := []struct {
		name             string
		args             args
		want             jwt.RegisteredClaims
		wantErr          bool
		mockResponse     func() (models.User, error)
		mockAuthResponse func() (string, error)
	}{
		{
			name: "wrong email",
			args: args{
				ctx:      context.Background(),
				email:    "hr@gmail.com",
				password: "12345678",
			},
			want:    jwt.RegisteredClaims{},
			wantErr: true,
			mockResponse: func() (models.User, error) {
				return models.User{}, errors.New("test error from the mock function")
			},
			mockAuthResponse: func() (string, error) {
				return "", errors.New("test error from the mock function")
			},
		},
		{
			name: "token generation failed",
			args: args{
				ctx:      context.Background(),
				email:    "hr@gmail.com",
				password: "12345678",
			},
			want: jwt.RegisteredClaims{
				Issuer:    "service project",
				Subject:   "1",
				Audience:  jwt.ClaimStrings{"users"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			wantErr: true,
			mockResponse: func() (models.User, error) {
				return models.User{
					Name:         "tina",
					Email:        "hr@gmail.com",
					PasswordHash: "$2a$10$uS/GmX48bxvhGPS.IrujaefuktoqGuKz3HBeOOMH6MGrnDT1H4TEy",
					Model: gorm.Model{
						ID: 1,
					},
				}, nil
			},
			mockAuthResponse: func() (string, error) {
				return "jwt test string", nil
			},
		},
		{
			name: "success generate token",
			args: args{
				ctx:      context.Background(),
				email:    "hr@gmail.com",
				password: "12345678",
			},
			want: jwt.RegisteredClaims{
				Issuer:    "service project",
				Subject:   "1",
				Audience:  jwt.ClaimStrings{"users"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			wantErr: false,
			mockResponse: func() (models.User, error) {
				return models.User{
					Name:         "pragalbh",
					Email:        "pragalbh@gmail.com",
					PasswordHash: "$2a$10$uS/GmX48bxvhGPS.IrujaefuktoqGuKz3HBeOOMH6MGrnDT1H4TEy",
					Model: gorm.Model{
						ID: 1,
					},
				}, nil
			},
			mockAuthResponse: func() (string, error) {
				return "", errors.New("test error from mock function")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := gomock.NewController(t)
			mockRepo := repository.NewMockUserRepo(mc)
			// mockAuth := auth.NewMockAuthentication(mc)

			mockRepo.EXPECT().UserLogin(gomock.Any()).Return(tt.mockResponse()).AnyTimes()

			// mockAuth.EXPECT().GenerateAuthToken(tt.).Return(tt.mockAuthResponse()).AnyTimes()

			s, err := NewService(mockRepo)
			if err != nil {
				t.Errorf("error is initializing the repo layer")
				return
			}
			got, err := s.UserLogin(tt.args.ctx, tt.args.email, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Service.UserLogin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Service.UserLogin() = %v, want %v", got, tt.want)
			}
		})
	}
}
