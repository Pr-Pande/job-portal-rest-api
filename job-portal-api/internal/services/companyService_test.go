package services

import (
	"context"
	"errors"
	"job-portal-api/internal/models"
	"job-portal-api/internal/repository"
	"reflect"
	"testing"

	"go.uber.org/mock/gomock"
)

func TestService_FetchCompanies(t *testing.T) {
	tests := []struct {
		name             string
		want             []models.Company
		wantErr          bool
		mockRepoResponse func() ([]models.Company, error)
	}{
		{
			name: "success",
			want: []models.Company{
				{
					CompanyName: "dell",
					Location:    "bangalore",
				},
				{
					CompanyName: "vipre",
					Location:    "bangalore",
				},
			},
			wantErr: false,
			mockRepoResponse: func() ([]models.Company, error) {
				return []models.Company{
					{
						CompanyName: "dell",
						Location:    "bangalore",
					},
					{
						CompanyName: "vipre",
						Location:    "bangalore",
					},
				}, nil
			},
		},
		{
			name:    "failure",
			want:    nil,
			wantErr: true,
			mockRepoResponse: func() ([]models.Company, error) {
				return nil, errors.New("company data is not there")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := gomock.NewController(t)
			mockRepo := repository.NewMockUserRepo(mc)
			if tt.mockRepoResponse != nil {
				mockRepo.EXPECT().ViewCompanies().Return(tt.mockRepoResponse()).AnyTimes()
			}
			s, _ := NewService(mockRepo)
			got, err := s.FetchCompanies()
			if (err != nil) != tt.wantErr {
				t.Errorf("Service.FetchCompanies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Service.FetchCompanies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_FetchCompanyById(t *testing.T) {
	type args struct {
		cid uint64
	}
	tests := []struct {
		name             string
		args             args
		want             models.Company
		wantErr          bool
		mockRepoResponse func() (models.Company, error)
	}{
		{
			name: "success",
			args: args{
				cid: 1,
			},
			want: models.Company{
				CompanyName: "airtel",
				Location:    "kolkata",
			},
			wantErr: false,
			mockRepoResponse: func() (models.Company, error) {
				return models.Company{
					CompanyName: "airtel",
					Location:    "kolkata",
				}, nil
			},
		},
		{
			name: "failure",
			args: args{
				cid: 3,
			},
			want:    models.Company{},
			wantErr: true,
			mockRepoResponse: func() (models.Company, error) {
				return models.Company{}, errors.New("company data is not there")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := gomock.NewController(t)
			mockRepo := repository.NewMockUserRepo(mc)
			if tt.mockRepoResponse != nil {
				mockRepo.EXPECT().ViewCompanyById(tt.args.cid).Return(tt.mockRepoResponse()).AnyTimes()
			}
			s, _ := NewService(mockRepo)
			got, err := s.FetchCompanyById(tt.args.cid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Service.FetchCompanyById() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Service.FetchCompanyById() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_CreateCompany(t *testing.T) {
	type args struct {
		ctx         context.Context
		companyData models.NewCompany
	}
	tests := []struct {
		name             string
		args             args
		want             models.Company
		wantErr          bool
		mockRepoResponse func() (models.Company, error)
	}{
		{
			name: "success",
			args: args{
				ctx: context.Background(),
				companyData: models.NewCompany{
					CompanyName: "byju",
					Location:    "gurgaon",
				},
			},
			want: models.Company{
				CompanyName: "byju",
				Location:    "gurgaon",
			},
			wantErr: false,
			mockRepoResponse: func() (models.Company, error) {
				return models.Company{
					CompanyName: "byju",
					Location:    "gurgaon",
				}, nil
			},
		},
		{
			name: "failure",
			args: args{
				ctx: context.Background(),
				companyData: models.NewCompany{
					CompanyName: "cisco",
					Location:    "paris",
				},
			},
			want:    models.Company{},
			wantErr: true,
			mockRepoResponse: func() (models.Company, error) {
				return models.Company{}, errors.New("compay is not created")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := gomock.NewController(t)
			mockRepo := repository.NewMockUserRepo(mc)
			if tt.mockRepoResponse != nil {
				mockRepo.EXPECT().CreateCompany(gomock.Any()).Return(tt.mockRepoResponse()).AnyTimes()
			}
			s, _ := NewService(mockRepo)
			got, err := s.CreateCompany(tt.args.ctx, tt.args.companyData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Service.CreateCompany() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Service.CreateCompany() = %v, want %v", got, tt.want)
			}
		})
	}
}
