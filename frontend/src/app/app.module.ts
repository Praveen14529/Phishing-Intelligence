import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { AppComponent } from './app.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { AlertsComponent } from './components/alerts/alerts.component';
import { RiskScoreComponent } from './components/risk-score/risk-score.component';
import {
  TechniqueChartComponent,
  RiskChartComponent
} from './components/charts/charts.component';
import { PhishingDetectionService } from './services/phishing-detection.service';

@NgModule({
  declarations: [
    AppComponent,
    DashboardComponent,
    AlertsComponent,
    RiskScoreComponent,
    TechniqueChartComponent,
    RiskChartComponent,
  ],
  imports: [BrowserModule, HttpClientModule, FormsModule],
  providers: [PhishingDetectionService],
  bootstrap: [AppComponent]
})
export class AppModule {}
